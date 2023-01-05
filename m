Return-Path: <kasan-dev+bncBDH7RNXZVMORBYWV3COQMGQEOFRKULA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC36C65E28E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 02:41:55 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id i7-20020a056e021b0700b003033a763270sf22258344ilv.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 17:41:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672882914; cv=pass;
        d=google.com; s=arc-20160816;
        b=LDBVwAT4ujrbh+bRkyygqijTBvRY9PjZnKOKrLTjWHnjE3mANF6UsTOhtSBqFWtWxS
         ohoB0qSmbsTKoGXlBGpeBEOQuNcgX/92ypEv1Uub4YYexaGxjRz8VZlBv+gHWqQfdG0u
         o+WNKKxYA57foMgBBSmdZafU/NJiAFrBN8a/e3F8NTulJK2aYpd9Jxp8hDW5oXsjJ7Sb
         kvbpQyg3hFt0GgZ5XvWc/VR88T/CreVMLqjZivlgi4HFALEq4U3lKWAUPQkcgt60Ex0j
         S0f/cYqwGSK553bSvAUA8knpaM8r4btqMMJ3ZhNIVVctGsaJ6RRc6i6M7OPFrrwqgKYy
         lhNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=e3jx+X8ZcCMjmCiCmqey9qWHLaq6bvcXizopPsLc7SY=;
        b=yaJgSGbLBXOr/j5ccFYztMkA0Cm4ytwjNi0E59C56g7LFU4tTDXbh+crjvEPI+PXLe
         eH68CfF2yJPQSYVcyfe0iuI0mwoxRuW3+rzEfchuuB7qvSZAF0aQHbDFVTSR0koXqCvN
         rkKhwaC2ROiLYT6ljaN/at7JS12n5uGkX7SisWHrD8v4J0WXbJAsg1Jf8uK9BpugUdEi
         v1O6uzEd11877s4JHm9caXPsU/ecGGoc3RkQAYy5A9WWOCPTbPF10XdLd9bx3o2LDlG/
         a2GDd/rOJVOsmY38CFt6tHgD8eZ8Sg5zgLmwQGDv3TVNTJqNcZYmI+AstK1cUjRQ/2hi
         lFxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mNT9PCRm;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=e3jx+X8ZcCMjmCiCmqey9qWHLaq6bvcXizopPsLc7SY=;
        b=C2e4mzY9+q4zRwz9Uqqa6PDO8xlPJEYpxpjYLX+Qt30Y7+xW4O24FfRiD3vhCIyTiv
         RNlkNIJvHZLuPGaWX/sdEzl5xF59NZXGArgvDpqqhDACEvoyGjcZfWStBUCsBbAQSRat
         Dadgk+Wif3N/AGKFl72AMI7Rm3ZXRVIzmTyf08j+wFf6uly4WqsYOVE9jIKQ9lyUc7n9
         N0TFhEuFC77pKDLf2IRjH0FZsupzWJF88CB7ktd7cb8eaccTOvrccXq3N65Y3ksiiHRW
         A/i+SFztDmxgpDNBqI6zh8QjnRw5al4Bl8khzAU4koYmENNMycFlxqbDswsMJ9Rt2KWp
         RGmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=e3jx+X8ZcCMjmCiCmqey9qWHLaq6bvcXizopPsLc7SY=;
        b=0TqWJWyFfTU5Tsa6/zondlqiWIrRpmdt0vFpmarty5Kd4SPEzTRp2GIth/NUiA7U25
         +KEp81jcWL2A0BhtQuLxtjxp4jGzVq95VuuuQ93tjGKiw1ZaarG/QeXehB6/E4H0gHhu
         r8Gq9FK2gez7HT84xquCKwByl16mEY8/+27S421ufJM0g7K9HwOAti7TQeGyCAByunks
         J5xGyY0NhBSW70Lu3SmDCO+sAedZ1DhLMmhm7SXf0DYzp6I+uBk+ncszHqLp0Ow6Hs6K
         TDqxQDNBUkKr6iCaSQptERT9krCJztmbE9I71jzRFhfJCHNEJd6OJJgCAcPwWvohl6rZ
         vbWA==
X-Gm-Message-State: AFqh2kpTcth6uq9slR1OhsjFzyVZAr0jbcSEFSPAIuIoMLcH3joUrCaj
	UM6AXzLU52Tqz2tWA906Jcs=
X-Google-Smtp-Source: AMrXdXsMTID180B8ArN3xeNcKvLAQYztp6HBv8PBlESzyOPIRSbeZgkYARoErxB/WmqlfAVjP90qUA==
X-Received: by 2002:a92:cf46:0:b0:303:cc0:689d with SMTP id c6-20020a92cf46000000b003030cc0689dmr3283913ilr.73.1672882914300;
        Wed, 04 Jan 2023 17:41:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1341:b0:30b:fbfd:3280 with SMTP id
 k1-20020a056e02134100b0030bfbfd3280ls5892573ilr.8.-pod-prod-gmail; Wed, 04
 Jan 2023 17:41:53 -0800 (PST)
X-Received: by 2002:a05:6e02:1146:b0:30d:6f64:d844 with SMTP id o6-20020a056e02114600b0030d6f64d844mr2931437ill.6.1672882913745;
        Wed, 04 Jan 2023 17:41:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672882913; cv=none;
        d=google.com; s=arc-20160816;
        b=W0cs3CjdXXmZVAgWWbFoNptdYa/nNQ4Z6uMnXXfDaRaE84hSiU2siufYkbbZT12aMJ
         6eeUCTxu8duo9ENU8Hv6w6+dMS/53MTlNym4Dxq12FXlAuf4cuq/QbzKZNRcHrebVEVw
         JZXgBHfGV/HloiEtNDCeEdtn+39L+GkUf9hVvZd5LzvryIulXo1bMH+B4hzmEYXVuCIF
         TZtPkcqcxcuKzetr+3RvYclZvjqiDwgtfYAImgfU954BhHc9iFkJQ0GZHUula9cU50sx
         RgFkjMOPyESGwoABgD5BzOZDohGIWvxWMwOQVxPlPaBcjMsG9gvujTaSNoXCOJ0s+bAI
         OY2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=qGDoBgnyiYUBevy+lcv+gZmYeTZ3heicEZ82qgGjf80=;
        b=pBCUjIGe+Qol8y83hahZog3tGR375Dt3tIKAAGSnwYL7QtEHcO+vstHe1efQjOuZKH
         R+1G6fFIW4wpoF4x+hn5i2MqXi8IrhyagcNwzqppFmwH62u0xOyCfe6SbabZ9Rz6wvtl
         PuSAOleP4xRJRuKRCZfxiigu3Jt7oNkxoxHZZGf6b0p1HW9l4mX5tCjkbMPsROtvk/wL
         QGDxQNfbpF6B6lBCEXWEXqGTc53TpIgQpy2dZcVUJhLbx0z0xK5TDkgETjN78XQ/0xNU
         bhlH4wxai6Sxw93OZdRi38CU9vvoX15SkOraQFWmCaux3JEXZOVVdIO6adZFWuBw7n+h
         aVhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mNT9PCRm;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id c9-20020a02c9c9000000b0038a6bbe1e21si2631254jap.1.2023.01.04.17.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Jan 2023 17:41:53 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id g16so28254425plq.12
        for <kasan-dev@googlegroups.com>; Wed, 04 Jan 2023 17:41:53 -0800 (PST)
X-Received: by 2002:a17:90a:c903:b0:219:f970:5119 with SMTP id v3-20020a17090ac90300b00219f9705119mr45423pjt.1.1672882912921;
        Wed, 04 Jan 2023 17:41:52 -0800 (PST)
Received: from [2620:15c:29:203:fc97:724c:15bb:25c7] ([2620:15c:29:203:fc97:724c:15bb:25c7])
        by smtp.gmail.com with ESMTPSA id w6-20020a170902e88600b00183c67844aesm7454159plg.22.2023.01.04.17.41.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Jan 2023 17:41:51 -0800 (PST)
Date: Wed, 4 Jan 2023 17:41:50 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Feng Tang <feng.tang@intel.com>
cc: Andrew Morton <akpm@linux-foundation.org>, 
    Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, 
    Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, 
    kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [Patch v3 -mm 1/2] mm/slab: add is_kmalloc_cache() helper
 function
In-Reply-To: <20230104060605.930910-1-feng.tang@intel.com>
Message-ID: <8d8a3e03-d019-df20-9525-ea4b4043540f@google.com>
References: <20230104060605.930910-1-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mNT9PCRm;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Wed, 4 Jan 2023, Feng Tang wrote:

> commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
> kmalloc") introduces 'SLAB_KMALLOC' bit specifying whether a
> kmem_cache is a kmalloc cache for slab/slub (slob doesn't have
> dedicated kmalloc caches).
> 
> Add a helper inline function for other components like kasan to
> simplify code.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d8a3e03-d019-df20-9525-ea4b4043540f%40google.com.
