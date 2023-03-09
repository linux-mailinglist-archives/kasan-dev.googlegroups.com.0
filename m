Return-Path: <kasan-dev+bncBCS4VDMYRUNBBU5RVGQAMGQEXFENXAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A37836B3032
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 23:08:21 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1765e2031ccsf1801941fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 14:08:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678399700; cv=pass;
        d=google.com; s=arc-20160816;
        b=SN3LjoanTo5xAyuSAxchGB3A3Eu++ErmFxLzF5693IETN50UOCphh+YjYW9CE1eVdl
         voLFfUUWqYzeNKU25WChqtsKMzDzWm7dgRgRJqVfiZsc3FOSTGSc8nVfYQJR0MvSDOA2
         8+3eLAvC7fsTIJxU9Rewn2ykqp3faYmoYTIpDDw2ZwrkqeZpwqDOQWJEkjgdmBdbA8qF
         OEah/CdhioZDrSsb5z04pvKfnPePGYznKdkFt935yY14jV4+siJ7ek/umtoYQQzsAIho
         Olqle39LxPsmMWLLzx9hQPWAkeg42dr7JMr4ly7RtfefO+GxoFePwL7hkT+k43A0UCz7
         0jRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=MZP4BpCs6NYrOkgH3Uy+IarPmxOm5p5hQBS7dDDcuCo=;
        b=nOjXF90v/9mnTJQ7b16dYDBype+f/w87vX7ClsT8TQH886CbbHL2ug7or0NnpOYI+R
         ZyNNHMcj/KR9g3VeqCrsvNhq7rHofYq04nEA7j5BbqCGbAEtiWEoQEYXmxrXaO0D3n78
         z8hFQyp2xBCl6hIvUNBLpHbxO6rcdqg2srWqbwUQ7eHacggUsSa9S7YViDo5Ju/jPfnz
         501GlX/rQf1cvgeo78fLeIc7UNtXsQvV4gRGJeJI8fXRbdKhRbD7JmihCevkkx1b59ey
         1XmdP+r0qu+m8KrHyIfA5G4vhUy0nekH/zOz7//8NOZXGel1E5hs5s6hacpUg1UfJ2jD
         OMJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yu+MLyjR;
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678399700;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=MZP4BpCs6NYrOkgH3Uy+IarPmxOm5p5hQBS7dDDcuCo=;
        b=dQ7j/F6kC5+LEsZffxTVjuZu5JEwsVubaAyEjUR5YUwUT3k6QK1MhCleXHtkqNL9b5
         EuQqJ6OCnI1tUtS5iso52Rke4ZtRWsmNU2YJEGWkYzc5UtgYoxZQ8EBkcBYrTZY15ONR
         HcHZI60CRYL2UeX9vFolOFl1KEk19fLc33WxgOT/5Enbox65r4VftQSxBFN2UV5cV3/W
         aNEbHD7WkXhrtGJse1IDh6AuK/q0p+lYS3OobrWoS7jAXVWxLMCIxR3JyLyhl1zXGZOY
         KjH7vjN4WJ/0EFjG0CSB9m1bEhCzhakXpsCk6/tYTTsCv+SEOa3tZqkobw/ggtqbAIpd
         oRpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678399700;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MZP4BpCs6NYrOkgH3Uy+IarPmxOm5p5hQBS7dDDcuCo=;
        b=t5N0I4d367pbQcut9pdJX9NitQShZtpDmMe65QDzpRhgkVZoQcXU2JcnG2yE6v0Z/p
         n7Bpj+tVKjiX4AG9rqQjYPzmICUjPUBqgMKodFOsQSY1APizkJ1r1A9J0XGFWJLyMEPd
         rr+DQplR3uFxFVeZj5hNz84utHZrH9Bs7BUqLA3msd3emHYukgpNYp1vG7t7i6UyrQPn
         soX9haVUVDAcgmS3+JBLcphJhUBjb483Vjc7Qv7nGhCi7XrSHn2/YIB0X5Scvf35yLSN
         pmg3uiztTOY4RnP7FJLnvfMeikaCRveJcl9Zq+3sHNMfwcTRiSJqrh6wu3kmAkRlWT5t
         AwdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUBH5qYovqVnv8FNc+dIQ0pvDoJziia9J9xjqrirjsERikj1C49
	S1pOA40Q6dGedxjYa6r2fsk=
X-Google-Smtp-Source: AK7set80FI9MjYWwxNLv5OJRiaqxGiTHvGYxRtmcdjRQHXI4MuADbh8D1rpfJhuUiwwFHuVBWS8UPw==
X-Received: by 2002:a05:6830:31ba:b0:688:cf52:71c4 with SMTP id q26-20020a05683031ba00b00688cf5271c4mr7856079ots.4.1678399699976;
        Thu, 09 Mar 2023 14:08:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4f95:0:b0:363:b56:297 with SMTP id g21-20020a544f95000000b003630b560297ls826712oiy.1.-pod-prod-gmail;
 Thu, 09 Mar 2023 14:08:19 -0800 (PST)
X-Received: by 2002:a54:4810:0:b0:383:f5ec:b7e9 with SMTP id j16-20020a544810000000b00383f5ecb7e9mr9748891oij.54.1678399699413;
        Thu, 09 Mar 2023 14:08:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678399699; cv=none;
        d=google.com; s=arc-20160816;
        b=zm7fIhb0LP3dVKwK/lGsVW6lcXYtNO1h79IZD59xMkB4ooh/d+prgWlXLqjAsQqsXj
         EDUMut2KWyDrKhMrcZOpMT0INqpBMyW1Rv2rB3Oqo/oLtJhwnzK2JlC0w/Ts9LNo7EC6
         RF1jxNKzzZlf1PFTBSF4+0aQVS7p3yb/tPIWRmgiX8eyLCHe6P4dc14SN0LxjzRR770a
         LtNwxCb20emL9O8ZnZ952oJrz9A4MefFxWHh7KzqY8P6VHmtjeHxZK3bTntUqM3mP5+0
         EygValm0X1EE0r4lzzkxmydXW4IASKc2F/k9rnshjJCvU7V/AWcdd62s3uukcgO0X0h9
         OJJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RHzUNyPlCdW9hOteXt9Ey1a+TiXGlojAin3V0mR1cTc=;
        b=xNLSQywq1mJmI5mjuaSWmM4O+BBSqlfT90y6tBeraFalKzlbGr7R5t/wiwKbjFKhhO
         U53+VKu66/1z+E0oWllo9K1QKnErd5nldNwgS7WIi11qGQ/Opbt95Yi0JKg6q1RwI5F9
         ehcu1hdpzptPn9EM+zx4jSMfKWX84CpmXj7IzBNlM149kophm/HMMD8wKUGBaXLx06dt
         nNuOjTvsQx8XtPYd83uJiYEkQ9n/8pxkeHa+O9KUGuVRIbeec315vodIvl5WzRQo5Mie
         Hd6xlS78azvb2SgPBqaT53MAGxnG6e5f5rUe1WA0Bqc+otysCx6lrD2N+A8p5coLy7yb
         0GVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yu+MLyjR;
       spf=pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i62-20020aca3b41000000b00384e4da7e50si15511oia.0.2023.03.09.14.08.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Mar 2023 14:08:19 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 28E6B61CD8;
	Thu,  9 Mar 2023 22:08:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8C540C433D2;
	Thu,  9 Mar 2023 22:08:18 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 143211548D6E; Thu,  9 Mar 2023 14:08:18 -0800 (PST)
Date: Thu, 9 Mar 2023 14:08:18 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Haibo Li <haibo.li@mediatek.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH] kcsan: Avoid READ_ONCE() in read_instrumented_memory()
Message-ID: <510ecaa9-508c-4f85-b6aa-fc42d2a96254@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20230309101752.2025459-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230309101752.2025459-1-elver@google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Yu+MLyjR;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Mar 09, 2023 at 11:17:52AM +0100, Marco Elver wrote:
> Haibo Li reported:
> 
>  | Unable to handle kernel paging request at virtual address
>  |   ffffff802a0d8d7171
>  | Mem abort info:o:
>  |   ESR = 0x9600002121
>  |   EC = 0x25: DABT (current EL), IL = 32 bitsts
>  |   SET = 0, FnV = 0 0
>  |   EA = 0, S1PTW = 0 0
>  |   FSC = 0x21: alignment fault
>  | Data abort info:o:
>  |   ISV = 0, ISS = 0x0000002121
>  |   CM = 0, WnR = 0 0
>  | swapper pgtable: 4k pages, 39-bit VAs, pgdp=000000002835200000
>  | [ffffff802a0d8d71] pgd=180000005fbf9003, p4d=180000005fbf9003,
>  | pud=180000005fbf9003, pmd=180000005fbe8003, pte=006800002a0d8707
>  | Internal error: Oops: 96000021 [#1] PREEMPT SMP
>  | Modules linked in:
>  | CPU: 2 PID: 45 Comm: kworker/u8:2 Not tainted
>  |   5.15.78-android13-8-g63561175bbda-dirty #1
>  | ...
>  | pc : kcsan_setup_watchpoint+0x26c/0x6bc
>  | lr : kcsan_setup_watchpoint+0x88/0x6bc
>  | sp : ffffffc00ab4b7f0
>  | x29: ffffffc00ab4b800 x28: ffffff80294fe588 x27: 0000000000000001
>  | x26: 0000000000000019 x25: 0000000000000001 x24: ffffff80294fdb80
>  | x23: 0000000000000000 x22: ffffffc00a70fb68 x21: ffffff802a0d8d71
>  | x20: 0000000000000002 x19: 0000000000000000 x18: ffffffc00a9bd060
>  | x17: 0000000000000001 x16: 0000000000000000 x15: ffffffc00a59f000
>  | x14: 0000000000000001 x13: 0000000000000000 x12: ffffffc00a70faa0
>  | x11: 00000000aaaaaaab x10: 0000000000000054 x9 : ffffffc00839adf8
>  | x8 : ffffffc009b4cf00 x7 : 0000000000000000 x6 : 0000000000000007
>  | x5 : 0000000000000000 x4 : 0000000000000000 x3 : ffffffc00a70fb70
>  | x2 : 0005ff802a0d8d71 x1 : 0000000000000000 x0 : 0000000000000000
>  | Call trace:
>  |  kcsan_setup_watchpoint+0x26c/0x6bc
>  |  __tsan_read2+0x1f0/0x234
>  |  inflate_fast+0x498/0x750
>  |  zlib_inflate+0x1304/0x2384
>  |  __gunzip+0x3a0/0x45c
>  |  gunzip+0x20/0x30
>  |  unpack_to_rootfs+0x2a8/0x3fc
>  |  do_populate_rootfs+0xe8/0x11c
>  |  async_run_entry_fn+0x58/0x1bc
>  |  process_one_work+0x3ec/0x738
>  |  worker_thread+0x4c4/0x838
>  |  kthread+0x20c/0x258
>  |  ret_from_fork+0x10/0x20
>  | Code: b8bfc2a8 2a0803f7 14000007 d503249f (78bfc2a8) )
>  | ---[ end trace 613a943cb0a572b6 ]-----
> 
> The reason for this is that on certain arm64 configuration since
> e35123d83ee3 ("arm64: lto: Strengthen READ_ONCE() to acquire when
> CONFIG_LTO=y"), READ_ONCE() may be promoted to a full atomic acquire
> instruction which cannot be used on unaligned addresses.
> 
> Fix it by avoiding READ_ONCE() in read_instrumented_memory(), and simply
> forcing the compiler to do the required access by casting to the
> appropriate volatile type. In terms of generated code this currently
> only affects architectures that do not use the default READ_ONCE()
> implementation.
> 
> The only downside is that we are not guaranteed atomicity of the access
> itself, although on most architectures a plain load up to machine word
> size should still be atomic (a fact the default READ_ONCE() still relies
> on itself).
> 
> Reported-by: Haibo Li <haibo.li@mediatek.com>
> Tested-by: Haibo Li <haibo.li@mediatek.com>
> Cc: <stable@vger.kernel.org> # 5.17+
> Signed-off-by: Marco Elver <elver@google.com>

Queued, thank you!

This one looks like it might want to go into v6.4 rather than later.

							Thanx, Paul

> ---
>  kernel/kcsan/core.c | 17 +++++++++++++----
>  1 file changed, 13 insertions(+), 4 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 54d077e1a2dc..5a60cc52adc0 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -337,11 +337,20 @@ static void delay_access(int type)
>   */
>  static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
>  {
> +	/*
> +	 * In the below we don't necessarily need the read of the location to
> +	 * be atomic, and we don't use READ_ONCE(), since all we need for race
> +	 * detection is to observe 2 different values.
> +	 *
> +	 * Furthermore, on certain architectures (such as arm64), READ_ONCE()
> +	 * may turn into more complex instructions than a plain load that cannot
> +	 * do unaligned accesses.
> +	 */
>  	switch (size) {
> -	case 1:  return READ_ONCE(*(const u8 *)ptr);
> -	case 2:  return READ_ONCE(*(const u16 *)ptr);
> -	case 4:  return READ_ONCE(*(const u32 *)ptr);
> -	case 8:  return READ_ONCE(*(const u64 *)ptr);
> +	case 1:  return *(const volatile u8 *)ptr;
> +	case 2:  return *(const volatile u16 *)ptr;
> +	case 4:  return *(const volatile u32 *)ptr;
> +	case 8:  return *(const volatile u64 *)ptr;
>  	default: return 0; /* Ignore; we do not diff the values. */
>  	}
>  }
> -- 
> 2.40.0.rc1.284.g88254d51c5-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/510ecaa9-508c-4f85-b6aa-fc42d2a96254%40paulmck-laptop.
