Return-Path: <kasan-dev+bncBC7OD3FKWUERBMHSVKXAMGQE6CZXSYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A2CA8523D1
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:34:58 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-598cba51c4esf3385022eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:34:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707784497; cv=pass;
        d=google.com; s=arc-20160816;
        b=LEOBYTeGWIbU6Yx49g7vNAck9U6+0hQopoEWSVpsZtujzAo8nStjlilUVcV4MHb8lu
         LgccON0YBuJsXeIF/D9HFuydJQDaGYvjzAdtpbzJu+b8pApyebO7EJn7AhfUz3+8/j9q
         yi0nrEcaCNrpJltPHN1hPNysBZifYQVINr6mIEz/bw3uQMBLw4TG+C+eO/dxHEvCHN6I
         Z6Jf3cjYLkRsU8ng7TTrm9xcw5cNnjuST1kSXr9RPexlq6RFbrbEFYj4w45HEzYbrFrj
         71ok6bYP1HgkaEOV6mqfSgDQt3f26VJh9L9GpYVGTe2l+z5TaGjsPmsWy8tOceNdzsa5
         nB5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0RbCahpzR3PBUsbF5wcfSMC7gVK8p9WcONfQsiEll4M=;
        fh=GAaKini6byimHAcN222fS2izd6f8GZRMM0UtWksQn4A=;
        b=rSd3JK3LNucMQ+JGV8p9z1jC0l/CdYbWXUueI3ZP940SXjYgWHBwkZlaY/pUfWL2JQ
         gDgeH6t0xow32EddMuGb8Yclkuxq4nFWq6fNRZH35AeSrIsFPIIZ77cHIWtbbfYfVJiV
         jwPp9WCSpLSJztIi//PyWZY/rgdao9w9CgkHlGeJmIqqXrvjVUnn+gq60vzA9vI+pxeP
         9b4y8RW417sgxZvXyqZaXcKBBBSK5R8qlUIQCE/zymxSNmdKViUXbkVh1wM+pWF2gt6c
         RX4tI+1OC6rZU/rpZHb53P/i/yHrT/59iXg90EcJoOByzbgXWgBWF870+GxwJBhrhDUn
         F/Mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cL6JZggq;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707784497; x=1708389297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0RbCahpzR3PBUsbF5wcfSMC7gVK8p9WcONfQsiEll4M=;
        b=RIA5f0FrrtVIa37/T9r3jxGVfWNZsefBdH8A8DBwZ9D2GOchJMzLysl5SJquC2L7PR
         W3SvyPCin/WJ/TtUGhQiVhZuPA1gS9yJqvHNbjhe/NQCxSZd4MIdmme5D8zNWPz7TXfC
         fbXrlfV5Ook+VQ+BuXQOPEk1BKVTRbvL/0Yd8j7JkFepPjVzeE4JgShQQ2qp4mptQgu7
         pQjOfxorATZ6JKKyy3FtuoQfhaIWw3+3s37rARWTd3GPlAOqq9fULki79tPWXs8b0Hy2
         48klUeKNEpLpQR7PNyLVF3aipygwGM1FiHoFRE2/Wu+DzCLZtoPZjybebHCBMaWT71fK
         mhQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707784497; x=1708389297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0RbCahpzR3PBUsbF5wcfSMC7gVK8p9WcONfQsiEll4M=;
        b=np8yUyv1+SHWEVZ+kFpM5aNdtSH1DDAwwGuIIF3D8S6jAciMTS94456N6tagdzc3CU
         JerCOAXPpJQBViPvbcDS3cyR8WnPb8MnL4kIclupGGwPn859zJcdmbs4y7246+H1Fec7
         yCC/iRL68iN7ivfaEB7M9V79lU2JymEXPHpcHIP2fu5+EHIM0p/D82DoczvnZv6BNwiV
         tEz72dC+L5vVz07g1P7wYJ1porFThLwk+I+Beg9ClgSngPDYZ6/8iMG611mjvsPOzwrC
         EZYFhHfCvUghNOJtAVQ7okYUEzIxgMt2QJw26fp5rRpYeYafFBnx+qTAw+l1RJus2FpC
         VJoQ==
X-Forwarded-Encrypted: i=2; AJvYcCWMXJRrcLNItEkLLjXf4zm9Q08F2YWBOr94/9MKLSEEx5/zKfSLwIZDUqvY5YJ92rnLTO1ow9eoM7U92mxNu32EUuXiQ/xurA==
X-Gm-Message-State: AOJu0YwOeZP1Hhoaq28iuTb0dSx9ndeXgSR37oo3ao2TYsM04+lAHn5/
	WzyiY7XRSJkoNnq7LUEuJViavfVhRqlazlbtV6QwkOT516/AeB8i
X-Google-Smtp-Source: AGHT+IHV+r6VkLaufkmIGg2L8stV5tFOxYRBvEo/56PByeRuX8mSCLRHGYfvMx63HziXzWWfdRDv3Q==
X-Received: by 2002:a4a:245e:0:b0:59d:3888:aa9e with SMTP id v30-20020a4a245e000000b0059d3888aa9emr6156648oov.6.1707784496943;
        Mon, 12 Feb 2024 16:34:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5850:0:b0:598:a0ac:c96e with SMTP id f77-20020a4a5850000000b00598a0acc96els742563oob.2.-pod-prod-06-us;
 Mon, 12 Feb 2024 16:34:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUetFozDW3cjjdODNCrvUT4UDsdJ8GxD3jxvYJoGWxck940NsqXTwUd43/SQdMvog72QpZfh2MMjggFa3HAyiO9x9TRrwc75zqUCg==
X-Received: by 2002:a05:6808:1813:b0:3bf:f3a2:cda0 with SMTP id bh19-20020a056808181300b003bff3a2cda0mr8932261oib.42.1707784496202;
        Mon, 12 Feb 2024 16:34:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707784496; cv=none;
        d=google.com; s=arc-20160816;
        b=tGyeFhyH2CNZ4BOokfBbGbc0YP6jGbchkhqiOlYG2lf7JBj4dvZxpANA5sT01aunAn
         UbbIM4hiwZq/oc1CYe+JDiKokpz77sohNWSLtzHS5U6V3G+73LVcb9SgGJKcJRCzLV0e
         9QuuRcu/NdkjR5+cChZHIAIJ06Fh+eRu+cenBkDqN4jhsJFnODR0oJJcq4aZsK1nApec
         yoweETuqwzbdh7eq/08DCGCcmh+yi4lnFk8bqGfkp6/ItgwuCnITPTAu78jTCsdWPQho
         FM/V/InyOIhkYzbNuX226U3KxhMH6SyfVl1oQ2lWEjB8T/XVV+Ar6qi5byTe0Z7nzq2Q
         qoHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UHD/3jMRU1ccG3YkQIqWf6JR5thVdXFBz5XlT+Q0DtQ=;
        fh=JmcA65Z78dOrqkqKahXq+QkQynIiQeTcIu48KrSbRHU=;
        b=MSrU/H40ECW/UCtwV4Ra5BG+rzjtXK2VL4SEvH3OSRpNiPabXY2wuPkqeuVzITORLt
         BpJ+O2XnU+tKqWJMUnItVORtASVZD4qsSLmM9VrDoZRCQbtXhxTlcVup1AXowKr8Mizi
         V3X+hjpF2ugEDgcwRjUJvm81hCgYFFdpcYzE/Ysp4CN2/UjS5tgpneFPiiBSvteE/8Qd
         RaKM7v3I1Bzemknqf2KxM7sbjWG8aLbzq5QuaSANAkPkOvEQPTXMY7Rtitd0/38FyLdg
         iPcL+rcE2Zz8u68JBe0jd409k1f3/iO3eUW5TERRmCkQT+ZN2KnC+sTrHyQTKZBDxVP8
         jUkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cL6JZggq;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCWVniOFSHbKKupwT07MbSdHPQDVC0fMk60VTUjjKktMKgeHxth37u/skC8emmM2IlmEdbaFQ8AywWS/Um8u/iqluKcEtrAY5pzu0Q==
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id cn15-20020a056808350f00b003be119aa0b5si181423oib.4.2024.02.12.16.34.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:34:56 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-dc6d8bd612dso3743502276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:34:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWCtlPTc9YId0CSuhdlzoXlvwohfbMi2sK0dHs8Y76N2tOOqpUkU9fQInYu5BxvERU4e+RFa4CoPr2feH+3PsYMGP00qHtTjGH+kg==
X-Received: by 2002:a25:b389:0:b0:dcb:ca7e:7e6f with SMTP id
 m9-20020a25b389000000b00dcbca7e7e6fmr1832315ybj.55.1707784495521; Mon, 12 Feb
 2024 16:34:55 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-24-surenb@google.com>
 <202402121631.5954CFB@keescook>
In-Reply-To: <202402121631.5954CFB@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 16:34:44 -0800
Message-ID: <CAJuCfpHf+EUPL7ObG7ghVhQShcJJSwMjNcUAzeg-x1BoS5OeEw@mail.gmail.com>
Subject: Re: [PATCH v3 23/35] mm/slub: Mark slab_free_freelist_hook() __always_inline
To: Kees Cook <keescook@chromium.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cL6JZggq;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Feb 12, 2024 at 4:31=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:39:09PM -0800, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > It seems we need to be more forceful with the compiler on this one.
>
> Sure, but why?

IIRC Kent saw a case when it was not inlined for some reason... Kent,
do you recall this?

>
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>
> Reviewed-by: Kees Cook <keescook@chromium.org>
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHf%2BEUPL7ObG7ghVhQShcJJSwMjNcUAzeg-x1BoS5OeEw%40mail.gmai=
l.com.
