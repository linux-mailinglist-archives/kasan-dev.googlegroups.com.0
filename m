Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMG4QG3QMGQE2GQMW2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id D313B973CEC
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 18:05:05 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-27bc0c2270fsf2101837fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 09:05:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725984304; cv=pass;
        d=google.com; s=arc-20240605;
        b=KsytcJPvxTM6KYP+btjZahJamXr0ah4oPeXSUIbnDcfhsWX+xuk8jLilQFCNuq3yyg
         9x5PWNU9KiKvpzom/ugfBKIoF3ZP9W56XUi4UOuGP1KVAOpyUKl/gsqAlMcZtzc2DvZe
         pNPxjLpxW6eDxdt7o7lftEYCGLI1FCeHYE9MXY5YcMB9tL4YJhU0r/9d9y8Q5Lb8ZOFr
         PIc4Jn4mWU0CMsQkeV679yw1GLNc0dUv6wKwhqpX2bKEP0G2eDJ52zrnC4tW50tThPSo
         fUUNdFItBPZhwuPMaeaJIprMHWPdL8VpveVEIkPlMaGnzZ1uANpgP5D46t8ndRpkRgs0
         3cVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PxGixF7/+8Cbo9HDlWf1a7fP5T3Q6YH0ZMn+JR0cjoY=;
        fh=ywlJw6POzvzhubSalf5Mkzg6sBve9aZmlw7hZMqen0M=;
        b=J3OUjDGhAyeoTHtcxw/+Uy1kESKfwhg89XWEv33EYSdH5//rsC0Wd0Sw5SxgJKszL4
         Qr7sluxVkkkBGNjlypJ7mV2Rx72l8ukQJS9m7YRogAM0ktl42aonXCHbcffmj/Hquh2H
         omjfxA7yEKUARJMMLH7ATWzAPT2v0dC4Us/KhEMJnc5i3KSvI3mq7j4UxAk73ltYl6Lb
         XmQFOqnpyFkSe3Y/xi+6yc0DgxUA2AL5o1vy4gZc5scLH/BLUj1H/+muk6eV7EbTlnAr
         P6oPzIk8IdZdo/O/UMM7AshQfZKtcd2OXCFeCnGwl7UuNExcAI3e+0GQfLj9XREODlG0
         HUyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="M2/J/m+3";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725984304; x=1726589104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PxGixF7/+8Cbo9HDlWf1a7fP5T3Q6YH0ZMn+JR0cjoY=;
        b=fAHCP3XMNN7hDzgfM+9mWGCiHPKKAtZSGEr/+KF9b2tp735lKsrJdQqqxfRVH5HnRq
         x0su6V4hoBgOc1BgBJv73QveZQ0CoQFah0Dnz+XJ3nYkpV6oQTPaZzrWnBkOUpuRXg7P
         i9Q+XXx6im6SKTw1VYI4hgNFpSYB/6sRFcHumWj6daHAh1D+M103OlRvvjBAueFSem8s
         P7Xjh71dM69kzdF8mfLiUGEHjrbme9zftriIST9ScIb9hZHItYYl8qbrzNLNKFjWZl+Z
         /76y9Pcw8LDrvXsgquZBTxTMtBXPmJh0BI681GY550F/TmaHILtLKmVRoC/VvL9+kz9Q
         UPkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725984304; x=1726589104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PxGixF7/+8Cbo9HDlWf1a7fP5T3Q6YH0ZMn+JR0cjoY=;
        b=r77v9lxwYbVATq79AMYDpCCpRJuvNAcwj+W7vZXmDM6eBcFg0ATj87Jj4JyFSDrL4+
         FIaMR2HFt/4wn1TaZ5K29hDWJUjbocLcpzvqdGpFyb/WQka8yBHzvMXcv6X6bwNXpzdn
         d8cXEJY4M61HnkMCGQ3p1F8A4rpvPP77+F0S1Y+hkaJFaBPW9lCfUWwKYzBQ31bENqaj
         B7JoUyQ+e8kKmVC0zcQ2sOK+yILo3FtEVU2cP8FWYoQWx4ZGKtodoDi/ZOgV33AC9cyN
         ILvnF7DAVb1320ev8Gtq3vJ2dfSHTWZKN4Z+c3FZIltDfPB5XC7XiHTsOjixiil/6tVT
         8Crg==
X-Forwarded-Encrypted: i=2; AJvYcCWZEyt89v7Wyt+cfbFxZQLgGDZhzWLqU7dbJwlh6CJeaBWWwkBc4tF58ReiXJU5VWMPIrlokQ==@lfdr.de
X-Gm-Message-State: AOJu0YxStPQ9o9SXrooy2aQZqFoUX4PPHSXwJgiaZ5ifXGhAS8U7FofJ
	9nigD14bLwvmqEZz94n8PT5NFyV+3UPqz8DeQoy6IBNtEGaU319k
X-Google-Smtp-Source: AGHT+IG1qjnUbAFZmkJfLC4Y+7EEB89ttHAfUMD3BtcLTQuS5b46RNYzcCNpOL3fvTpUKdn3AssSeQ==
X-Received: by 2002:a05:6870:8321:b0:270:4219:68fe with SMTP id 586e51a60fabf-27b82dd1e37mr15475622fac.1.1725984304654;
        Tue, 10 Sep 2024 09:05:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:670a:b0:277:f19a:1140 with SMTP id
 586e51a60fabf-27b822a2c69ls5081965fac.1.-pod-prod-05-us; Tue, 10 Sep 2024
 09:05:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUufl4T1DtjZuR27gQcHi4uYqO1drTxYhVdH5t0ECFbXyLo+5eE1DOgo8G7xTrpQfH+VipcPXBfuKA=@googlegroups.com
X-Received: by 2002:a05:6808:4442:b0:3e0:48b2:3f40 with SMTP id 5614622812f47-3e048b24281mr3863737b6e.45.1725984303680;
        Tue, 10 Sep 2024 09:05:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725984303; cv=none;
        d=google.com; s=arc-20240605;
        b=UlZ08QXfQJXRTYJpAJD4kbpWzhWFv/YXMUI2VV1w+scPYZTpyGUy8oB+kyhBVAZ4Sk
         8sOeXuyzNeEetC5LZrWcD5hijandlBmoISXvAbWVQ3vPEtd5nKcNr7nJmhKAEpnXiQyn
         EnblGn9z/ydloB+tjBNyThnMrQsYBt1inCvIBTpuLmm+KApspYXf0SWkRbkLEm7wpo05
         nMYg+B8OVXGTSuVLZ2TuOMc0UUSQIXbcrkYgPG1qrqbu84V5dBcOe2cyrwZHaiQgBOJV
         vXx8RnHnZNUPnlgamC88iTJOjO6CN8lm+Juff9q1lOLIjb2FxDgnXboYVLN8b5EA0ifP
         bMOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P1siuBJeF8xo/ZxDywGlXBwlCjIfSaO4qNxoqL+UhoM=;
        fh=0y7T2L+1IE1uRTEnhSMsIwYWvotD3J7zfC4trAMLW7w=;
        b=U+HYH8wK/F/HOkRxmQKGeWMmYJTTbBXudUqMqtBTNgoupCCwGxtHg0uPO3hbTLh7Ws
         wBsA8Mi8KLz9sj/dQtbTffbbGuFOoy90ub4lkdLeBWV4O5GxO+ZaldZKnwvHt3jiTz9t
         ZQ2aukgQaGjxzo0kj3DL8V+3rGZPVH5nr5Ti9n1XYtBZIIrwca/AP0c4X+CTwZTW6Wjz
         SYum9xUHBIm5hfh3aUk47+VCloSC5GWaMebS+OUocgrFpB0WR7IbNRTXuryXvQKW+NAT
         uZaKzbnHQwFJ5v6g7KdDEoeSbKL96f/YieeBpsljwBsIDaURD5r5CkVhKfSr3zLGy+OE
         uHBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="M2/J/m+3";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7d8273ae987si370878a12.5.2024.09.10.09.05.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Sep 2024 09:05:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-20551eeba95so51111795ad.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Sep 2024 09:05:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKbDM+CmfLFyupegO940WOB7oEg31nEPNNs00y4Kpoew11EIb9NUX93mA2cJjwvDItN39R9bkKQck=@googlegroups.com
X-Received: by 2002:a17:902:ea02:b0:206:b399:2f2f with SMTP id
 d9443c01a7336-2074c706ff9mr17118845ad.47.1725984302684; Tue, 10 Sep 2024
 09:05:02 -0700 (PDT)
MIME-Version: 1.0
References: <20240909012958.913438-1-feng.tang@intel.com> <20240909012958.913438-5-feng.tang@intel.com>
 <4b7670e1-072a-46e6-bfd7-0937cdc7d329@suse.cz> <ZuBURfScdtDbSBeo@feng-clx.sh.intel.com>
In-Reply-To: <ZuBURfScdtDbSBeo@feng-clx.sh.intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Sep 2024 18:04:26 +0200
Message-ID: <CANpmjNPOO1kj62wRUJC=yZ4qhvHaDDTpH68UQ-MT_jZU3Giaeg@mail.gmail.com>
Subject: Re: [PATCH 4/5] kunit: kfence: Make KFENCE_TEST_REQUIRES macro
 available for all kunit case
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>, 
	Danilo Krummrich <dakr@kernel.org>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="M2/J/m+3";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::634 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Tue, 10 Sept 2024 at 16:14, Feng Tang <feng.tang@intel.com> wrote:
>
> On Tue, Sep 10, 2024 at 03:17:10PM +0200, Vlastimil Babka wrote:
> > On 9/9/24 03:29, Feng Tang wrote:
> > > KFENCE_TEST_REQUIRES macro is convenient for judging if a prerequisite of a
> > > test case exists. Lift it into kunit/test.h so that all kunit test cases
> > > can benefit from it.
> > >
> > > Signed-off-by: Feng Tang <feng.tang@intel.com>
> >
> > I think you should have Cc'd kunit and kfence maintainers on this one.
> > But if that's necessary depends on the review for patch 5...
>
> I added Marco Elver, Shuah Khan, David Gow and kasan-dev@googlegroups.com
> for kence and kunit review. That should be incomplete, will add more in
> next verion. Thanks for the reminder!

Reviewed-by: Marco Elver <elver@google.com>

Glad to see you found this macro generally useful. But do await KUnit
maintainer Ack as well.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPOO1kj62wRUJC%3DyZ4qhvHaDDTpH68UQ-MT_jZU3Giaeg%40mail.gmail.com.
