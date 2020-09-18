Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE5ASP5QKGQEO4DYBIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id CD6022700C7
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:19:47 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id o13sf2173935ljp.18
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600442387; cv=pass;
        d=google.com; s=arc-20160816;
        b=y5qlMQTjKlMpNHMu43m4g4Pqb6mvTR/vlM8dbfmhqADraj9zd4FVE1cqxIfj+fopox
         G6LIzmou70KRuYDmQFD80p9g+iE5531mcGIxzLDBuf4jkguZbcM/iBO2nHwIJXVazwag
         n/wKGqGI0ACuUcgfrG+Q5nKKiqpgJ4BzPdYUgScArk1MMLQl7PXNbKcQxNtj+NeqS3Lh
         xH6comCrmlsa9AMgXP24llc4QCR/dkQdYESxC5H/wx95rSyhc5c99BudA/Q/AGJ+17Ab
         LnfuY8jI6Ykja/nHeZIwnRquOBIwrb2JPAP+4W487MID9WgJm4FPq8UEWu8zKYjRKnRO
         m0vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=j6gNlQatICT/hACXrGIWabg5frhJl8mAIUTr1ud6bHc=;
        b=takw4XZbvsInxtEtj149/nC45o9jMOOC8qXB1axOptXFDtvSd7NVeeDoUj3GbxdT5/
         hyzRHg8O7YJmkay15JCU+HOmdqCzNiN8U+X3SvVj4Sj3LGwQiUtwzesE8a5AGM4aUE9r
         iYLkr2FpotnIVHGuEGuablfJoO8zy2j85FBNppa6fab665ZxrhlshJEpjADsbMPEOrUp
         qep/qyLoQeoe+bQWGjshY970MAbDIq9iAZ2J7gwXdYtBulwwby5rIm9RNMwNImpFX80q
         KahGTRcOoDXpzJSyYQkyPBAxwGGE44kRQ7h/xaZ6BezwB/n+WIQsodVhn3NSJXvIzQ/U
         OBHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=njwtxF5o;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=j6gNlQatICT/hACXrGIWabg5frhJl8mAIUTr1ud6bHc=;
        b=B54GrqRjZHlLnXD4BJQDWVUz1qwTU3tgfjQEpfin/MJ1+COlywnepVDfghL56zLCyt
         vub0Mmi/FJ8ddYA278HKEsUQ8LDOQ1fWYK+PTaxE5RKx/gzmgOiZxld2Usu6ninzuMpt
         6ar5Ud7ePTZy4hI5K1J0Ri1i93ggmBBAyaS79RKl5YBELZjOTZ0uy5GMtzph36uUGr2S
         kNH0k/WrQ1U8iYRtLorsW6pTYzqzRMDuN2ofPmxQK7/S+lLdJSE9reD2/UV3IjGmDGv2
         DeSj8Wffty407E3vWgJMsaSHEPTcaO6oMWM8xxjsUcqprP9/7MPCOvWLJQ9vbtDVVgP4
         NeTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j6gNlQatICT/hACXrGIWabg5frhJl8mAIUTr1ud6bHc=;
        b=NxNH8b/6sXVPzpgQko+METGSyt4G64e/balbwgXinXht2qJhQKFNFvnV1yKH1zc1wZ
         nbRxt5gGB6otz0s3kefv/aSmKsPgwkBYzR85xeEGEgv+9i+dSRvSAz9YWs0vfEVhOPe2
         8bFTmQ54PTLAjd0Vyz97wMHrvT5aPL6vt9+YYE4aR+uvX8RfINwZoMMJYd+LbMc3Bn8V
         fJb30g1BxdkBpWBTU8QMBTJHdwKgeBbspiLquxzmxt/rIvueEpXFRTJ+daAq9+xtCBB9
         LMPzSxI9tLE7sH1mEVoSwAiTgJVLpUSpcPOBeiu4P9MGYFaGoxV8BQhMgj1OG+d8aFIq
         IzhQ==
X-Gm-Message-State: AOAM531Eh0VtYOq4Tta4tzOeQa4d5XnSobOYU5gD3mPTJWYHp4LITz47
	I/E5yds35krHPYBticcp4wU=
X-Google-Smtp-Source: ABdhPJyh91awddQ51WhRUVROSQDtVpbOxe9Mnv1CFcIubN0cyHVcnnthz39dEpUz5PGje5hCMcTpaA==
X-Received: by 2002:a2e:898a:: with SMTP id c10mr10871377lji.4.1600442387288;
        Fri, 18 Sep 2020 08:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:93c7:: with SMTP id p7ls891732ljh.11.gmail; Fri, 18 Sep
 2020 08:19:46 -0700 (PDT)
X-Received: by 2002:a2e:2ac3:: with SMTP id q186mr12495559ljq.419.1600442386056;
        Fri, 18 Sep 2020 08:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600442386; cv=none;
        d=google.com; s=arc-20160816;
        b=nohRy8atQAj5RV6gTGNbdvU6caDXsg9Hxqtb7D3MH/H61zp4m5BaQsfmaJE19lec83
         2gTEPRZpGdun+L3MTeS0pQlWhu2LJ8DHSwVAH8NnwDWUp3SoeaPs7b9AeMBOs7BAwY5d
         xEZIRzQ55M171r2DwxwGURZJSiDlH7igJVw45GegD9FowJFrRxH7IScCZMMv9tM1h+Ql
         i0kqe0Q4DhTOudTm1AHbLigSZy6ku8q/kY5SqWsem+lxtzp+OaU000zHV69Z7jeIljQN
         TbdRZgSXjpBVjCpirDmRODI/g1WHd8iNRnqGrIsXkzN22Fv4CAdq1Z3RHGR/QUAFJDMt
         1TTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LN66O5JSkYCxOmUnEcN+noTfKpC7LQl7RqBfE76tpKc=;
        b=PK76KRJBWm8LQgDruN+Y3qHVVvFPXaXI9RYQS7W+y0McJtxZfibJ1Coj89dKV9xuvv
         kplgw+4tg5x61Yjus3Oo/dXiK4h/mQF4ARlMdlvNEXcpee6xppZUbvtH4pjnEcj1hPiZ
         suGPiTOmTxle10kOyVSYhSYVfhcNaMw2WLDAkO3K54t1hxihcCpmyKHvSNNjfEz4qGVJ
         lb73WpVfPSSjA30vTD0Ss95x0a5y4ljJMrO3AQBcC/ua8isHEiW12nX9H0CB80s5Wljn
         IY/EAarKchl7qu2w0H9VMKx9T1FtpR+DjKg91uGoc3yNgzTFGIYna9lqJATV5acniugZ
         ySuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=njwtxF5o;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id b5si84641lfa.0.2020.09.18.08.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id s13so5682922wmh.4
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 08:19:46 -0700 (PDT)
X-Received: by 2002:a7b:c085:: with SMTP id r5mr17054390wmh.52.1600442385292;
        Fri, 18 Sep 2020 08:19:45 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id v128sm5556561wme.2.2020.09.18.08.19.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Sep 2020 08:19:44 -0700 (PDT)
Date: Fri, 18 Sep 2020 17:19:39 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
Message-ID: <20200918151939.GA2465533@elver.google.com>
References: <cover.1600204505.git.andreyknvl@google.com>
 <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=njwtxF5o;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 875bbcedd994..613c9d38eee5 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -184,7 +184,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>  
>  #endif /* CONFIG_KASAN_GENERIC */
>  
> -#ifdef CONFIG_KASAN_SW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>  
>  void kasan_init_tags(void);
>  
> @@ -193,7 +193,7 @@ void *kasan_reset_tag(const void *addr);
>  bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
>  
> -#else /* CONFIG_KASAN_SW_TAGS */
> +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>  
>  static inline void kasan_init_tags(void) { }
>  
> @@ -202,7 +202,7 @@ static inline void *kasan_reset_tag(const void *addr)
>  	return (void *)addr;
>  }
>  
> -#endif /* CONFIG_KASAN_SW_TAGS */
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
>  
>  #ifdef CONFIG_KASAN_VMALLOC

It's not visible by looking at this diff, but there is some
#ifdef-redundancy that I do not understand where it came from.

This is what I have to fix it:

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 613c9d38eee5..80a0e5b11f2b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -40,6 +40,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
+/* Enable reporting bugs after kasan_disable_current() */
+extern void kasan_enable_current(void);
+
+/* Disable reporting bugs for current task */
+extern void kasan_disable_current(void);
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
@@ -50,18 +56,6 @@ static inline void kasan_remove_zero_shadow(void *start,
 					unsigned long size)
 {}
 
-#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-
-#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
-
-/* Enable reporting bugs after kasan_disable_current() */
-extern void kasan_enable_current(void);
-
-/* Disable reporting bugs for current task */
-extern void kasan_disable_current(void);
-
-#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-
 static inline void kasan_enable_current(void) {}
 static inline void kasan_disable_current(void) {}
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918151939.GA2465533%40elver.google.com.
