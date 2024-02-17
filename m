Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEPSX6XAMGQEIKNJQMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 517FA858A87
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Feb 2024 01:08:51 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-29935a0ecbbsf1022649a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 16:08:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708128529; cv=pass;
        d=google.com; s=arc-20160816;
        b=jQzn+b8/047hVkvFp46Y8iXQyPFculTk2fAIHH7OlgUurXlzQWzX0lBkxfgf7jI5K5
         6eXJorsEIP8KRFrh8k7zXZ5AlRfzRX8Fg+lEsHdEHnPnwZJfHFJDWxrVXy1e8tivDvIq
         tJN/oAIgoJZV+80aMgmhiO3dnng0pZN1zHsT07MWJKmEEeEuV0sNKGducEEJBw1hPeXK
         LcZ/QvqccNmvuP6Lp2W68j2oFxkpI5dJkPqYQz+hztuTFSLS5/aB2uzMmOGwo/n7LaS5
         ih98EnRbOTpRFuSCUqWftu4ddJ9Us2hB6vycWI+Ey0URN+XXVRcQidcWYG70nr2kVEgV
         Li+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=V6rFA+palnMR48lvpwOO5rJ8HeBrIzf89TneDch04q8=;
        fh=hDanGQp/Wl574y9TrkBFwQsJmEkRZz31vGBIAOkcLoM=;
        b=nhIUtB5nqKz8fhm3KJo3qYYFhJekPr+1LoTTRHdEBypZSYqAlWKULBX82xzIfpZ0Rd
         QFKukjbmJJlICrO1FI/mkte6eb+JwwhD8cwIBWxcR13WgqW8Rtdz32L2aJptUWW5bbnc
         cWrhbTjCufuTPmimpH7XeBA7c3CL/iCpz0BMdDw4zHQZJdwyVsgFQZoXoO2Qp9qTqMF7
         0FQ3aseigfhkuJXmOpJlLC4Rwwm8hxHFjeLPRyNYqf6PCmGAwETwWrzyIWVycXP0x0aa
         lirpui5M0imwmdUxRaZe0PVUb+5vnuzQy2yO9endRxgt4kavh5NxfO3zqmv7i9Tp6+Ll
         TwEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=buuh6wt4;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708128529; x=1708733329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V6rFA+palnMR48lvpwOO5rJ8HeBrIzf89TneDch04q8=;
        b=FVHf9FMyPFin2M4MV8cAE4FWPVVEA+RfmekxDKukVDyThJ39baUMJb9CgV4zRgyTTY
         V68/F1Qr9FPYqi17kU147UN3pAAGGEwMw2S+kcyZEXEyvd9UfWB8G03EhkB8UninGO/y
         rDLnpFsKTYX9tfpiTMKQTpIEGH+x3DL/4pKfHesmDH6jJJDgzwJoHDN0BNg4Gl4mFlOl
         1ipnCIT2x6cSLcwZ2KVUnF7PWCCGqH5OS9IcTki2EBMMDO4JICZrWI/+wAKzjpFjTzuM
         JURpHzI8+GPAfHeN+K+AVS540d7m+IyjqSS0ELWNecq1RkD8IJx62l78lP57ou+oHXkH
         Ca2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708128529; x=1708733329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=V6rFA+palnMR48lvpwOO5rJ8HeBrIzf89TneDch04q8=;
        b=VaUeMTPShm9sX4DykPK10pohttXtYMtKzUSWji48shHa6/pLqIQJ3AyYc/rJOwsmGn
         mDR8gEZwxR5XMhHmWoJ+FDGrU8dAJryX2RX/SqD8t5fKAQfm0tr9V798BhYipRAoN0UT
         KjxdLo5N+uQOu5FB5mqEm9eRdDRRRN8thVNAfJH+1OaS6e/eMagY7asuvbBB18IyWgI7
         QMgyjXMobJw+86hUZ/qA1U5niHTtlkgFO9XdyQ3TZHWz8Jb1Wn1h2gSDZ2nSAEYra7HC
         9Gx1yI/kUcjg7ab0CdDArnsiXj74LdB8QENwd5C/r/TuqTwmI2Omd47nNpiT/qw0Lw3W
         BWMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX2S4RWfAlBA/6xTPBzuFdU0x7rGTLKmu6QhCpDn48rfvHDRIHsElT3IYaVzjyJBB0R/q0oigrEnQrbo2tR0CM5CT/0Lqabpw==
X-Gm-Message-State: AOJu0YyFyQW0/A79PmuTiFdCFh+leTtprp9DxFJlEQTobdK2iq4uWIwm
	OaUFOyUtXT1YXqPGgZkabbfmF0ROG2qbq7gGCwMWamEoLGBKMQa1
X-Google-Smtp-Source: AGHT+IFvVUMUVbOF8SoixwOeFgY9WEvSZNk/RYbkC2USzrkfZbIJfT/ad2EswIWifMob1bmHpCWcRQ==
X-Received: by 2002:a17:90a:db41:b0:299:4ad7:b263 with SMTP id u1-20020a17090adb4100b002994ad7b263mr1360390pjx.29.1708128529406;
        Fri, 16 Feb 2024 16:08:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:394f:b0:299:2986:44ab with SMTP id
 oe15-20020a17090b394f00b00299298644abls1061353pjb.2.-pod-prod-06-us; Fri, 16
 Feb 2024 16:08:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVHqx0XCHD8CIKqeXiaBUyFuq3R+bUuFnrHlzkmye3Ek8fU0o/xwdS8rPRwDWJC5dkR4xVyAG0RTOObopd3HsryHJQM/Ho1WfbABg==
X-Received: by 2002:a17:90b:14c:b0:298:e3aa:c2e0 with SMTP id em12-20020a17090b014c00b00298e3aac2e0mr5866981pjb.13.1708128528402;
        Fri, 16 Feb 2024 16:08:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708128528; cv=none;
        d=google.com; s=arc-20160816;
        b=pTHeegoEIOcup6PvhRpvxUqpVpa2NO0DSyW3Y7naNGqQkjVJ5TPcBvATJuNgfbcXGO
         t+McXW+p62gCae6Th2Z0bLLS9TvbtlbNA2Goaw28DHRklvYhclbsNeyVfInfynb9FBmG
         F7LjcYJ69tPGZToE+GL+zYRSid8qfk+pvD0/hlfNJDSst75x18igMksx+acyCShEWC7N
         ZXwASd46cLhY7wTeuaceYweYEkhuOFevPHz7m8rf75nAMIa7Ue3ZajjPcAcAbvztQoRu
         RApPE+84I9FXr/kxGQ4SiDfGbppgNnhujnxEGfiPN0YWl9310HQ1JjLwzwsDbvOvHtnz
         6GMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=S1txfacIBFBZ/O4tjcxs+bfhiTiZyaDvYXwzko6DwYw=;
        fh=S3U2261Hl9SHlJ+cR+fYX0ybR4lWAGcH/uzOzf5gfoo=;
        b=FrNuZO26isl5vauHuhmwuay7tGmRY1qKkQcXFpXqC6DKKZoq8T8z0fv4BLc1RMZMKf
         J0Agi7g8AsVRaW8nbLboEmN+5wW9ExE5CjFcHvtD7rcoPttC45x2THfmjqLgDRd4KpSE
         BKoRXV0mF5DtU6rVU2gApK7Xz2OyfJGXUFNJOxMpR5wSfW0ETLYKo05HsFASOyDdyZGf
         xLwXGN8fU3FtA5gpzBhHL+XNTkfh8ClO5tUVTljx4vKvJMI+8r04OF6Qk2wFvr749Zv4
         39m0okfZhbWsxzqTXkJScgpI/WlyLKayIFY37DqpAof88oH2EO+iwjiK4mo42wy10p4y
         dLGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=buuh6wt4;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id w17-20020a17090a8a1100b002994adfff69si88229pjn.1.2024.02.16.16.08.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 16:08:48 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2995185dbbbso270360a91.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 16:08:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUMfxVi+xj3hpVvUsB1gyqq1F4ypMK5TQ8ZxRr0ODWyeDMGcLlKEvbZaU/3Q1vb6FMZURZWx0J/usdN67/FLcnR29LrkYCvpmKdsg==
X-Received: by 2002:a17:90a:e602:b0:299:29bd:ee1f with SMTP id j2-20020a17090ae60200b0029929bdee1fmr4886121pjy.0.1708128528040;
        Fri, 16 Feb 2024 16:08:48 -0800 (PST)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ds5-20020a17090b08c500b00298ff26e4c8sm572039pjb.26.2024.02.16.16.08.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 16:08:47 -0800 (PST)
Date: Fri, 16 Feb 2024 16:08:46 -0800
From: Kees Cook <keescook@chromium.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <202402161607.0208EB45C@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook>
 <lvrwtp73y2upktswswekhhilrp2i742tmhcxi2c4gayyn24qd2@hdktbg3qutgb>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <lvrwtp73y2upktswswekhhilrp2i742tmhcxi2c4gayyn24qd2@hdktbg3qutgb>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=buuh6wt4;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Feb 16, 2024 at 06:26:06PM -0500, Kent Overstreet wrote:
> On Mon, Feb 12, 2024 at 02:40:12PM -0800, Kees Cook wrote:
> > On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote:
> > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > index ffe8f618ab86..da68a10517c8 100644
> > > --- a/include/linux/sched.h
> > > +++ b/include/linux/sched.h
> > > @@ -770,6 +770,10 @@ struct task_struct {
> > >  	unsigned int			flags;
> > >  	unsigned int			ptrace;
> > >  
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > +	struct alloc_tag		*alloc_tag;
> > > +#endif
> > 
> > Normally scheduling is very sensitive to having anything early in
> > task_struct. I would suggest moving this the CONFIG_SCHED_CORE ifdef
> > area.
> 
> This is even hotter than the scheduler members; we actually do want it
> up front.

It is? I would imagine the scheduler would touch stuff more than the
allocator, but whatever works. :)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402161607.0208EB45C%40keescook.
