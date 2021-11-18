Return-Path: <kasan-dev+bncBDV37XP3XYDRBKHI3CGAMGQEWLPMMZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A20354559A2
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 12:08:24 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id x17-20020a0565123f9100b003ff593b7c65sf3789230lfa.12
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 03:08:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637233704; cv=pass;
        d=google.com; s=arc-20160816;
        b=t6vYYWbJES/AU2FH8fYJ/tR6GH+XYe4RKTuZVBRuanrNv/LIMAkbV1m7iPghaGQwd5
         BpqoPWG5TwUWinXqQkqDC/uxE6GVZFMQC2+BjTPBkGr1RZywI+oYox28KH8mwH2aQlkj
         2IJohfnprtinCSZw0Hx7z/FIwd9oDWh5Li0a8mhi3E9tTp7+M0w5aT5Hmui4UuMZGfdE
         sKFhaZanQUb+10IuhqX4YtdXqGfZpL7A+DlEPItpz97k4itqggSQKQL8+2TyhUCQxH7P
         CpemBZ+n+PhTf/RyyIyXhwCIJS5omUFJb1DM+0dslYVq1tOWsX1Bo1UFCJlUZ+c4M8vi
         q2tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cXkbOhEi3wXEwgJdhKhWu0rCBRUvO0fPkgYLNsdFVfU=;
        b=WADxELPWmTsNUa55y/LUpctjQUgxthUeneCXQBzZ406YYQYTg4h8vJ5ic02eoqbbuB
         NIheKB36poAVJNwD2ZTuh/Dd7alka6DJUGwXePdbG52o2dh0hML6xN+E4hQ0TacRl65l
         yhfL5GGres2hnxIlkM8Gwvwdq3TkDc0b2bSGNghcZ8lG0fRLz4mRgUy/5hrRe+nvN5sm
         Ejti+6RzkMoLBRKgsyiFERrNoPBhtU07PzJJImV7fFo4qwR4uIB0edAGnTn0Jn5aNgq/
         2CSDbv2C+sEYe0YxdQu2sa7QRvX5aFr01wM5sglTjKMNriJNp9m/SdHz1xbJXmjclh0m
         8tOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cXkbOhEi3wXEwgJdhKhWu0rCBRUvO0fPkgYLNsdFVfU=;
        b=dUx2Y7QtpuqlG67iVaA7UC1cKcTA7O7RJY1oX+HbaUS5QHpL0uIEwpJ9wcsOCw4WXu
         05X18MPpsMbBIVn8I09Hxw+wt0BsiM+Dl5SPrFBAbxCV1hc2UjG6VNRq5m4ZFXmALAxG
         lfWNQroW3SO2KeN0XQHZrK/CEQPLyOx5zrHTOFSeNnHhNliEtofndR8cRc8bbd3giEUK
         EG+Zy6+43hYsdTwCXOdAYbN8NNWl6oEeY/tjvo8jD9aBs5HSVyq31dMLXXCFVi6u2kSz
         al70gW/YceJlvDCm7516y0x7UMNHSJDvrFjUPWb2M+8i3wjiWhpH6YkW67EBTMWxulIj
         UlMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cXkbOhEi3wXEwgJdhKhWu0rCBRUvO0fPkgYLNsdFVfU=;
        b=sS9KuOD1JoN2wTGiCsmg1aGcYZyzbg/pu5mxySvF0HayHDdYOPK7OSRWymUyUHtmfi
         E9rmJTZPXQWrie1TYWHcStnp1u6Mir8iGF95QA2SC9ULADfIoNimPrTarf2GF4QYwprW
         HO/OiBE+fSaKH2oYzbOguTQW2w9kf3ZisfbXaLeQxCfg/+0QDeuXPAV8NEV+fsNcGdEA
         Bs7fdveT7qKKKLKBhKOsCNWYb/rIAhfQ6CGKacRff0fvDtJubmXU60ip7qmDoX/rHPpa
         3s0B0VXw3/WzzrlLv3txTiCm1lgEtaUH8BXWyKXjtT/ek1I56CEBmiSSWy++dda65M/y
         2+qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hlJFISkIB0w20KvgwShxlWF7DmxCHrlz2Nc2llVZHs4l7dsBh
	0Te2GRMFdWfgJ+JVsfkaLZg=
X-Google-Smtp-Source: ABdhPJycuv94CePYLRU96TPxLCqccHbTUt+4XxMydkve5Pc27mn6YJ+eombIwaThlY4nYQBxPAwt1Q==
X-Received: by 2002:a2e:5c87:: with SMTP id q129mr15367586ljb.424.1637233704256;
        Thu, 18 Nov 2021 03:08:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls1951920lfb.2.gmail; Thu,
 18 Nov 2021 03:08:23 -0800 (PST)
X-Received: by 2002:a05:6512:1310:: with SMTP id x16mr3121872lfu.436.1637233703135;
        Thu, 18 Nov 2021 03:08:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637233703; cv=none;
        d=google.com; s=arc-20160816;
        b=Uco0K0tDv5qBB06Uoed4e20WKRxOUNWI+wr02emTp8pkipGepBWkc5fODNBxlSFC2g
         XceoCdeuCKWKU6jEwSq5SvXl6XEtn1M03sPacKLOVEp8dSu6SIoDVf/ZescKTKhwt3n3
         BrNKxhfA4VldeCdBvhxK6dq33FrWEi9ChdZdnepeoWXE9EdKqtDZejD/xozYzl7z0uq2
         LRCQhZuFXux/D7MD1IIpwnQxP2kS1Rmv3VBLfxVrmjr/1RT4iYzpJ2ObAehVIv2qVu9C
         qcEcIh0Iv+uuTfx9ZWjVRVcvbfQEqdBD9/3cEV3lkv08W6Rd2jprp1JamLjpBjaG452l
         b+Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/abr01z3EYDOUESYJNw736mTWHWquEi+JvHBGL6q6rQ=;
        b=bGJqTq8zzuKEo6IKyw7hPd/frBeUh7vxpM5WaVI1hfEru5LUOrih8JnpRKRs68tYqu
         14Kxye3vFk/pxYfwn7a9PttWVV1AzXFRDzGvN2Ym7qgKqiDGx7U35oWQTFaqZbe2ZFRg
         0kwLLJEHdlm5ym6KnFUhl2SHscVuysCLcMsrZcPwjbRCFtC7gvqyYXYQ0bnH7MtUBmS4
         no//xZUrtV7XU01UKwIxxDmGzTgzss7eTf2bc7kWoABbxcYzOfmZ0NK6sDCjWqg0H2gQ
         iKrJ1tHPF7gv6A+/vvEr9K0o4FvQXlrTjLPjZCsW8wO76LC8IpxE6xMZ3ypp5lyb7cxm
         4K+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i12si188627lfr.7.2021.11.18.03.08.22
        for <kasan-dev@googlegroups.com>;
        Thu, 18 Nov 2021 03:08:23 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id ACE881FB;
	Thu, 18 Nov 2021 03:08:21 -0800 (PST)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 26D7E3F5A1;
	Thu, 18 Nov 2021 03:08:19 -0800 (PST)
Date: Thu, 18 Nov 2021 11:08:14 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 01/23] kcsan: Refactor reading of instrumented memory
Message-ID: <20211118110813.GA5233@lakrids.cambridge.arm.com>
References: <20211118081027.3175699-1-elver@google.com>
 <20211118081027.3175699-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211118081027.3175699-2-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 18, 2021 at 09:10:05AM +0100, Marco Elver wrote:
> Factor out the switch statement reading instrumented memory into a
> helper read_instrumented_memory().
> 
> No functional change.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Nice cleanup!

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> ---
>  kernel/kcsan/core.c | 51 +++++++++++++++------------------------------
>  1 file changed, 17 insertions(+), 34 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 4b84c8e7884b..6bfd3040f46b 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -325,6 +325,21 @@ static void delay_access(int type)
>  	udelay(delay);
>  }
>  
> +/*
> + * Reads the instrumented memory for value change detection; value change
> + * detection is currently done for accesses up to a size of 8 bytes.
> + */
> +static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
> +{
> +	switch (size) {
> +	case 1:  return READ_ONCE(*(const u8 *)ptr);
> +	case 2:  return READ_ONCE(*(const u16 *)ptr);
> +	case 4:  return READ_ONCE(*(const u32 *)ptr);
> +	case 8:  return READ_ONCE(*(const u64 *)ptr);
> +	default: return 0; /* Ignore; we do not diff the values. */
> +	}
> +}
> +
>  void kcsan_save_irqtrace(struct task_struct *task)
>  {
>  #ifdef CONFIG_TRACE_IRQFLAGS
> @@ -482,23 +497,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  	 * Read the current value, to later check and infer a race if the data
>  	 * was modified via a non-instrumented access, e.g. from a device.
>  	 */
> -	old = 0;
> -	switch (size) {
> -	case 1:
> -		old = READ_ONCE(*(const u8 *)ptr);
> -		break;
> -	case 2:
> -		old = READ_ONCE(*(const u16 *)ptr);
> -		break;
> -	case 4:
> -		old = READ_ONCE(*(const u32 *)ptr);
> -		break;
> -	case 8:
> -		old = READ_ONCE(*(const u64 *)ptr);
> -		break;
> -	default:
> -		break; /* ignore; we do not diff the values */
> -	}
> +	old = read_instrumented_memory(ptr, size);
>  
>  	/*
>  	 * Delay this thread, to increase probability of observing a racy
> @@ -511,23 +510,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
>  	 * racy access.
>  	 */
>  	access_mask = ctx->access_mask;
> -	new = 0;
> -	switch (size) {
> -	case 1:
> -		new = READ_ONCE(*(const u8 *)ptr);
> -		break;
> -	case 2:
> -		new = READ_ONCE(*(const u16 *)ptr);
> -		break;
> -	case 4:
> -		new = READ_ONCE(*(const u32 *)ptr);
> -		break;
> -	case 8:
> -		new = READ_ONCE(*(const u64 *)ptr);
> -		break;
> -	default:
> -		break; /* ignore; we do not diff the values */
> -	}
> +	new = read_instrumented_memory(ptr, size);
>  
>  	diff = old ^ new;
>  	if (access_mask)
> -- 
> 2.34.0.rc2.393.gf8c9666880-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118110813.GA5233%40lakrids.cambridge.arm.com.
