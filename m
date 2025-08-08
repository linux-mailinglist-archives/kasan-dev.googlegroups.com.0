Return-Path: <kasan-dev+bncBCKPFB7SXUERBYPN27CAMGQEPO6S57Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id D0D10B1E8E7
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 15:08:50 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2f3b98b0f9esf1503122fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 06:08:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754658529; cv=pass;
        d=google.com; s=arc-20240605;
        b=YIa+uIE6Jc365elQBQ0Ttce/85Z6zMdVAyNgtIAjItkMMfPk1lQPSg+DfHiGWB7eCo
         cJKbjFMFwag11rz72Mz0c0cmOxqJ1iwj8QGIZPL7Ho+fQm6aZRHKW88HdVTxLP/PvLob
         XLt3J/OuR//qDaTLJFO/jusP26mHK+nUXfUsZ2R74XC6NGuqf9Vc70ARKOMzqDSmcRzP
         G2bklx6MEuf0n+eRd6BQz0wqWfqZsO6O56sKQBZ7WD8t2oCzU0iau6vhy4dfpDn1JLiQ
         t7Tgi7V5KXJ0tobuKmuCjhcLxhG3wyYzLAKEv63FaxP7/OeNb+pHkO2+MEYrXm1axwgH
         TYyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TOKQ/RbQ8GSYyo+DDqQCxRvUdiF8zuH7Z6u1GysRSsE=;
        fh=Ew1gPprzDfVz2PYKWDrvTnfqgfp43IdBk5it2G9er88=;
        b=HX1KAy1RdLITgUlSxMZfbNxCq4h8hpTedw16g3qrOXbKU7aUmSCV8p3Z56e6WAZcCZ
         /MoKa444nvymiLrfapoD9qcMYyz7JNwz9x/3vpzlrBug0vDKwEkq2HaBqcq6GdKk+eZZ
         YZkgPE0hbZYLFpXupX8wEyKGZlQOC2LxVkKDEJ041ldzpYRuyxC8PGFvB8qSKxQznwG4
         LdFbVi0nJZuAcfhW49rYRAGKjJfOmcmDohMsVUnwTArpu3rhVMdsN18j0/HhDU0XQyMm
         Fx+KMLD6REYh+rNd91Ryuf/Ug9x0TUz+2h3sP54EyFK/6k31NPubjFTeqNWc9Twr/+RD
         nuUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eOug1dTC;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754658529; x=1755263329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=TOKQ/RbQ8GSYyo+DDqQCxRvUdiF8zuH7Z6u1GysRSsE=;
        b=OGDkKG91YelGh0Zk2Lao1wlO+XvU26u43pc7BrzIvIqln7zPU+fQyiIjRVNTsy7hfB
         awBcfv+EqZpK/8stV6SgbjArkSQ109LDSTbszI/8/LKVi6DdhhL2b1eRH+rgFE8023wi
         5LB8aiVggNJlpOkp98mK4as03gikZDpA94nLc7P2FQOZT1j9nduAsbINFsssmGsBzJgr
         tSizu1s/1j2ADMcEsxSqZ4zyNC3KXLuDPUyk5ftJAVtH7/lltSYUezun6Tr8pfbvRRKj
         +VvdT2RDwq0z1KIB32u0Dz0daS795/39XXsXQ2RYgeQ3805r6jclLhBrhbv8HMs1F5Kp
         /PeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754658529; x=1755263329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TOKQ/RbQ8GSYyo+DDqQCxRvUdiF8zuH7Z6u1GysRSsE=;
        b=fL13aj4wx5a7rEiFp1b3YPfyAa39o3YZ8ZRO8uIKcGl07SzJfoPejm4R7iPSKSfiAi
         NUvy0hABa7QyVCJKWyjA6NqcLEcRtcgqrv+MRTG75WAnL5vS4mHvtAa5+LFmq4ji0yv2
         0aABeeXWd+C6dSi4FVgDOFbl5nSnfTBEhJpneCaWtxUijMc+rRHmhsGlFyCHb3HgEJVB
         T6koEgF26tBtMZl+KkSIIujq8yZcSmx7Rk/Bt629TivhC8ea0PyJZGRkTPGdSCuk8RDN
         sOhjV7uq3uMRNPAaGa8MHkvZaCKWzjqsk+ubtuQb3jJfHYb9iyy0AXjFtkz9/WuCOMpK
         ePig==
X-Forwarded-Encrypted: i=2; AJvYcCXXsGDYUC4WED62m/RF2OsHYzSOycQ+Wf/k5IIAnHt4q9PQab+IjLgIUc9p76XlZj80PDmLIA==@lfdr.de
X-Gm-Message-State: AOJu0Yz15CbPhXdC3Nj4k10imHj2u1MSFOIAi0UQMr/LE+tI/dcRA9Pn
	W8cux5vdMocrMdtHhL12OscVO44H5H+M4HsutbnbbBhN2wKJpBjKCqt3
X-Google-Smtp-Source: AGHT+IF41dGpjQV+rIa3mazpm5Dmi/sO4lz66Nw4PuzdeRgX7KaVi7INh0RLTX27R78CxoFUb1Dagg==
X-Received: by 2002:a05:6871:7399:b0:302:f093:1c1f with SMTP id 586e51a60fabf-30c20eeec73mr1795395fac.6.1754658529180;
        Fri, 08 Aug 2025 06:08:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcDU+4L7yz0IXgqdXR/KbZt+7DYQ2URsoG6pDHicZ/Cbg==
Received: by 2002:a05:6870:c791:b0:2ef:51df:c05d with SMTP id
 586e51a60fabf-30bfe42819dls739391fac.0.-pod-prod-02-us; Fri, 08 Aug 2025
 06:08:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxz8yBU55C5kI3Q0D36cwqCb9vpWdZSCxBMHLbaxDNiJdQTQX7o45AwNAlW028Rp/fzkxTSXaJoho=@googlegroups.com
X-Received: by 2002:a05:6871:411:b0:2d8:957a:5178 with SMTP id 586e51a60fabf-30c21100760mr1762414fac.21.1754658527902;
        Fri, 08 Aug 2025 06:08:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754658527; cv=none;
        d=google.com; s=arc-20240605;
        b=W2fUIR3eWBGJ1YMCHgcuNP7L8lD8Q2RNhhMI2WUiVwAqXWyfr2rloTj8DBUYZH9jir
         pUJlApGH04TDXA4TRgYQwEQ/9UfhQqFUXU8EALa+E9IMiLE/4eHcZDxSRSNL8k42w6EB
         h/L027s6ZQVyiV8ky8gl067ZWxYkYum7oZ9OJYTp9wShlS0krqlvTVS7+AGNY/bB0aAy
         dnD77L35gYggXh6kxAF7ElIP41kNOQqrUilp8kwyUMDa7TMh4Kep0/2dYywUSPtGiTsG
         okjNHZOjHaIJ1gzDSxHl4wqvdA0tG2CmjmOqfUWgwd9jlwQLDeoxWOyjyyC0gakbJPVM
         8bLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=M0UiEs4Rh6Bq7jrDzS2r+cL0UHOZ82z9RlYdz/rMI4Q=;
        fh=/3jG9ethQoAl5TnrFc52/QqBLrrsYAKqXTTehFKeI9Q=;
        b=bZdTMcCpuUd71F+Inf7pyrchi53VT4xNPEJUvOcIHxEj/KiEQXsSJ8EbJHO13tKIDQ
         EVD2NK0iDZ1+r1YCZW0Vs+MM+GHdrd/kS506hg/786cszVWNACJED1lfp/TUtzif6jp2
         G+2RqcxGQP5nbfmglExCrnYtej3WrWrncG68SuzajpnekA6HeCdWHE+7tVjEqv3e9LG5
         rIsy/fOoM3dFD0QwlEPHbM4oK4PswwnSIEi9PxZkDgTunsKtDFDdC8UNPI2gQ9hbJoxb
         vk3XJvSJPz4JTGVyUQoZbnodULPAfdiVYURDZ8aoWEX7Sbq7ECGBqPaojngnIXO2tlda
         A/Gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eOug1dTC;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-307a67f3040si965390fac.0.2025.08.08.06.08.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 06:08:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-228-46aA9S8HOqitMnE-iqR_lg-1; Fri,
 08 Aug 2025 09:08:44 -0400
X-MC-Unique: 46aA9S8HOqitMnE-iqR_lg-1
X-Mimecast-MFC-AGG-ID: 46aA9S8HOqitMnE-iqR_lg_1754658522
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 03A801956086;
	Fri,  8 Aug 2025 13:08:42 +0000 (UTC)
Received: from localhost (unknown [10.72.112.126])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 1A81B19560AD;
	Fri,  8 Aug 2025 13:08:39 +0000 (UTC)
Date: Fri, 8 Aug 2025 21:08:35 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: SeongJae Park <sj@kernel.org>, linux-mm@kvack.org,
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all
 three modes
Message-ID: <aJX20/iccc/LL42B@MiWiFi-R3L-srv>
References: <20250805062333.121553-5-bhe@redhat.com>
 <20250806052231.619715-1-sj@kernel.org>
 <9ca2790c-1214-47a0-abdc-212ee3ea5e18@lucifer.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9ca2790c-1214-47a0-abdc-212ee3ea5e18@lucifer.local>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=eOug1dTC;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 08/06/25 at 05:26pm, Lorenzo Stoakes wrote:
> On Tue, Aug 05, 2025 at 10:22:31PM -0700, SeongJae Park wrote:
> > Hello Baoqua,
> >
> > On Tue,  5 Aug 2025 14:23:33 +0800 Baoquan He <bhe@redhat.com> wrote:
> >
> > > Now everything is ready, set kasan=off can disable kasan for all
> > > three modes.
> > >
> > > Signed-off-by: Baoquan He <bhe@redhat.com>
> > > ---
> > >  include/linux/kasan-enabled.h | 11 +----------
> > >  1 file changed, 1 insertion(+), 10 deletions(-)
> > >
> > > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> > > index 32f2d19f599f..b5857e15ef14 100644
> > > --- a/include/linux/kasan-enabled.h
> > > +++ b/include/linux/kasan-enabled.h
> > > @@ -8,30 +8,21 @@ extern bool kasan_arg_disabled;
> > >
> > >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> > >
> > > -#ifdef CONFIG_KASAN_HW_TAGS
> > > -
> > >  static __always_inline bool kasan_enabled(void)
> > >  {
> > >  	return static_branch_likely(&kasan_flag_enabled);
> > >  }
> >
> > I found mm-new build fails when CONFIG_KASAN is unset as below, and 'git
> > bisect' points this patch.
> 
> Yup just hit this + bisected here.

Sorry for the trouble and thanks for reporting.

> 
> >
> >       LD      .tmp_vmlinux1
> >     ld: lib/stackdepot.o:(__jump_table+0x8): undefined reference to `kasan_flag_enabled'
> >
> > Since kasna_flag_enabled is defined in mm/kasan/common.c, I confirmed diff like
> > below fixes this.  I think it may not be a correct fix though, since I didn't
> > read this patchset thoroughly.
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> > index b5857e15ef14..a53d112b1020 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -8,11 +8,22 @@ extern bool kasan_arg_disabled;
> >
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >
> > +#ifdef CONFIG_KASAN
> > +
> 
> Shouldn't we put this above the static key declaration?
> 
> Feels like the whole header should be included really.

You are right, kasan_flag_enabled should be included in CONFIG_KASAN
ifdeffery scope.

Since CONFIG_KASAN_HW_TAGS depends on CONFIG_KASAN, we may not need
include below CONFIG_KASAN_HW_TAGS ifdeffery into CONFIG_KASAN ifdeffery
scope. Not sure if this is incorrect.

Thanks a lot for checking this.
> 
> >  static __always_inline bool kasan_enabled(void)
> >  {
> >  	return static_branch_likely(&kasan_flag_enabled);
> >  }
> >
> > +#else /* CONFIG_KASAN */
> > +
> > +static inline bool kasan_enabled(void)
> > +{
> > +	return false;
> > +}
> > +
> > +#endif
> > +
> >  #ifdef CONFIG_KASAN_HW_TAGS
> >  static inline bool kasan_hw_tags_enabled(void)
> >  {
> >
> >
> > [...]
> >
> > Thanks,
> > SJ
> >
> 
> Cheers, Lorenzo
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJX20/iccc/LL42B%40MiWiFi-R3L-srv.
