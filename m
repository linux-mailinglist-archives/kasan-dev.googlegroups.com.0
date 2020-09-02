Return-Path: <kasan-dev+bncBC6LHPWNU4DBBWFDXT5AKGQECZL5AKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id B078925A40B
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Sep 2020 05:30:33 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id f9sf700637uaj.20
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Sep 2020 20:30:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599017432; cv=pass;
        d=google.com; s=arc-20160816;
        b=SHRj/RkSm/Vn3mVNdzEa3nKH55S3x+IjYtrp//d9M3asxqirwH3P7iYEgyw9bdb8UX
         U21ExZdaK0suKM6B4y086wOPLLlO5i0kWtrtsA9WaCDTFZ4jvyq0SC8cpecNG05mENCD
         Ffk677pcD32JeFN/uJieSeChto6SqE/KsdxWst92ZFdq2kqoLqwYtsYFm3w81oVLuv/T
         GQ0qagTLCUHjmpZh1qcqsXJYEXPzLO0ff42j7mBP/vYtsDU/w5JxQs3jDMfmwhK2heVQ
         pLHdcXIB0iO74QWyIjZ2vT5dHiQ5mGf0RKFC325oouNLfu4UuutBKh8x/zkugzh+2K5e
         LAkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=aMEfva1DF/r9IlQovMD00boCgQ5fWjhvhwHEeYEPo/4=;
        b=msgHCehMQbsBGDWZv0IHkbzV9q9HYfws+zhz/EpodXBM5uGx3Ir5krbdI14fwjubXV
         XgJC7lqfhMm3dFfN9rVnB8qqmpTo5KIOSma1L6/7P0aeVuJq5V8RMaSTBD1RPKbMnZ6y
         HS66iJpS+uPm4bTstpXzQATHBfffguxyQQ6fJ0lRQM6fUfIZJJRKTc3OmgbVeJGAp7aA
         x8o6jjOclkb0rhiUleqeeEPbjZ7VBr2XreR1zU0Cpw/+0QR8L18RB0DwmGIfOR7RfPtZ
         HqF3+LmkPdvAPiBSA3jNqoeKmZkdSVcMctGjBQceituZORsejJ5NoYQnSXSUGCAf46p7
         W84Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=TH5fADQT;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aMEfva1DF/r9IlQovMD00boCgQ5fWjhvhwHEeYEPo/4=;
        b=jDU3aq9k7J0oK3GvQlMaO0ka5860YLsPoz9u/JV6KTamNqKmp5gZieQkVHnRPv9e6t
         sYDZ6jwmvd6YyA1J350qWsBCb6vWXECn7cQiZU0ZAh5joXYiLR0l9pbpnJOkBJqDSzep
         nm+vQfLcc51DFz2v3jIXYyFiS4v0PiB4wjfDPbgRigGr3oSa95TXpftfQvLjwgiaPO8E
         RgHRrV7L0vC1UY3KO5o6vwGauFJ4U5OyMpvqO5+8dDqh34Am2koIkmiEsTpRTFEtZLgL
         hLBBPYRCucwcRExDMxLYrEDuBvvstlq/upuZDmbqa0YRWph2Wg6y26mDTenz1Du3DnLl
         AcYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aMEfva1DF/r9IlQovMD00boCgQ5fWjhvhwHEeYEPo/4=;
        b=SwaH5XhGeH+wt8ZaiH9xaN+qQijzMLcPF3hexUbR8pJJIis4eDzTcO6U4/UdAHv7wb
         rwuXgUwjZfANhrd3vyADunFA6zWjVhIko70JXI5aPyJavAT21iJ9owYJKzU0TkRsP1wz
         0HibB6n/575RMhzTFN3OR0RTdxUDhrWUzD9GzBZsREz9XifZ54iodg31dqCCzaiHGbRB
         kpSE0REzNJ0y+Rg5UUipx7xAKcwvFMgjweMY4p5w4armAX7d+X8hcyBJrCtOpSum+np5
         A6du15ZgyyDwyIa5hkD7iJK/isOfU2YKlmfCfb33joepHbN8mJ3SKqNS0pJh7DLIxQA7
         Bn3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aMEfva1DF/r9IlQovMD00boCgQ5fWjhvhwHEeYEPo/4=;
        b=ESyYxhxf9/KpQdWsSYQnKTaneNWAIhvjCwIGhOWw0fPhyku049Y/szjsFFCTMXJGCK
         JcwbtkDNWvpRQ6JXX4nnyNir0AXeRebWv4OwKvXxbLjJNmRo70LjuncIZQl+6in3gDdM
         hAEW8mV4ivKYgzYJpmkE/RbplkQx7jxmWK2pkDBqXUkzYZO65BWFPiy0NNtLsYn4pxLv
         seZ/zmvNl9OGWyTU4aEWShWqdNZ8R3wpPwksHuHZvqfO6odtKjJgrS28mBi6UFVZ8Zoo
         r1if1M1xU8996q2/lBZpH30Rucj8spKPjx5a/1/oCyyH6ZDS8/uALTwcTEjqhcZt8+MC
         Jdmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xDQLXl52Qbc7VM/dgk/ktB+uN0lQby8OI6kQQTwPh29Q7GY5s
	lFKVixnU6KvPpaL0y6mRa+I=
X-Google-Smtp-Source: ABdhPJyILU8vVgSSHUR2uwlwYU/kSjZAGxt1G3+DBx+CMoD9tBgY6+mzd6llyMOx/g9VxS1O0Pr4xA==
X-Received: by 2002:a1f:b254:: with SMTP id b81mr4087004vkf.64.1599017432640;
        Tue, 01 Sep 2020 20:30:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2995:: with SMTP id u21ls71360uap.11.gmail; Tue, 01 Sep
 2020 20:30:32 -0700 (PDT)
X-Received: by 2002:a9f:300f:: with SMTP id h15mr3945855uab.47.1599017432065;
        Tue, 01 Sep 2020 20:30:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599017432; cv=none;
        d=google.com; s=arc-20160816;
        b=u7UJ2gipv68P04+3HKBUjcKr6yHngcvfj66dsyo9ApK2RRritS5agJ8rvAPAgqPsvV
         me9r9D1xhHCpm8pf9VYwkH+uKPYCHY95d4FOAxRu6Fc7vxZxR/fiaSxzdmM9zUXSebuY
         9qCIkWz771VG/PbcbRrePGnnHGpRXcGw4cbeWLMQoSibutedyo1tVvbgiCsb8bFORgoB
         N11UR3LnJ3aJx7+7Cy9a1FzukAroDntQG452X60g/LI5NJjpmkMHZ9reb79yG34u52UE
         iEzWZUTIHs1PnckanJmfqStOhwfSE0L5S+R84jZLVKnNLlxNoMpsmOg1/2rZdukKEpaq
         7Nqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qMRTb7o6tIn+KisH8T8lV1168u11aqmlDTHJpu+vCTQ=;
        b=M/VhpkMpNHYdSHo7LOj2mb64yMgLBfsOaWTIB6q+NcWshUTXGZNfT42tuv74NHL990
         7i8jp6nBiu+5AYDTjXB3f63hBwD79tsyaScKJkb8Z2LmUy/4oxH4cBD755gNTkaPeKQT
         QCIZMEhJglbVE1fwlGZNxUCbzDjQ2oskIRkprRJ1ejIVaND7AlTbkx5JIT2KDaP6CYT6
         ICFT2iqsEjxqrClKhsazCfuoCgZ7WyAN7B254Apr4EibWEepACfqbEpKmb8l9hSk6nAr
         mnOpqpEGqtOWJzJDT77w1J64WepTqI6Eehz76IAxCP37yvP3DY2IlTyveSA48DdRcf8e
         A+ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=TH5fADQT;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id x20si95906vko.5.2020.09.01.20.30.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Sep 2020 20:30:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id w186so3158863qkd.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Sep 2020 20:30:32 -0700 (PDT)
X-Received: by 2002:a05:620a:2096:: with SMTP id e22mr5204355qka.177.1599017431655;
        Tue, 01 Sep 2020 20:30:31 -0700 (PDT)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id k48sm4335084qtk.44.2020.09.01.20.30.10
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Sep 2020 20:30:10 -0700 (PDT)
Received: from compute3.internal (compute3.nyi.internal [10.202.2.43])
	by mailauth.nyi.internal (Postfix) with ESMTP id C26DE27C0054;
	Tue,  1 Sep 2020 23:30:09 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute3.internal (MEProxy); Tue, 01 Sep 2020 23:30:09 -0400
X-ME-Sender: <xms:wBFPX3NzlpjwtBY4EJ9Vo1DpIzeZ9djSqDYyZs3QXRCygAQueXerBg>
    <xme:wBFPXx-WwpMENqbc2cWCj3ZRbqfzMalM4Ii2yuKF6x20oKpZaEHYG-Tc71TpeHRpU
    m2NaUWLE8D4oIenrg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeduiedrudefkedgjedvucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhepvdelieegudfggeevjefhjeevueevieetjeeikedvgfejfeduheefhffggedv
    geejnecukfhppeehvddrudehhedrudduuddrjedunecuvehluhhsthgvrhfuihiivgeptd
    enucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgv
    rhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfh
    gvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:wBFPX2QdrvqYHYFOY5RNAO3SxklCFWCRbV4Kts2GNCQrTVDp8D9GDQ>
    <xmx:wBFPX7vHnT94bpNT8kZlxzBcWvnMxWgh19WD6BC3Fdv-tTUoPqCdSA>
    <xmx:wBFPX_fQR15FDiGU2WP5D54xIve0z8c3zQ-_lqrScj6qeCiHriYzWg>
    <xmx:wRFPX6_YnMsWOtfcnnRfKBu131T7Rsy5qclM0NqIzfqcPo8T0kIFOyaU_10>
Received: from localhost (unknown [52.155.111.71])
	by mail.messagingengine.com (Postfix) with ESMTPA id 34A95328005A;
	Tue,  1 Sep 2020 23:30:08 -0400 (EDT)
Date: Wed, 2 Sep 2020 11:30:06 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: paulmck@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org, elver@google.com,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw, Will Deacon <will@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Daniel Axtens <dja@axtens.net>,
	Michael Ellerman <mpe@ellerman.id.au>, linux-arch@vger.kernel.org
Subject: Re: [PATCH kcsan 18/19] bitops, kcsan: Partially revert
 instrumentation for non-atomic bitops
Message-ID: <20200902033006.GB49492@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
 <20200831181805.1833-18-paulmck@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200831181805.1833-18-paulmck@kernel.org>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=TH5fADQT;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Paul and Marco,

The whole update patchset looks good to me, just one question out of
curiosity fo this one, please see below:

On Mon, Aug 31, 2020 at 11:18:04AM -0700, paulmck@kernel.org wrote:
> From: Marco Elver <elver@google.com>
> 
> Previous to the change to distinguish read-write accesses, when
> CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y is set, KCSAN would consider
> the non-atomic bitops as atomic. We want to partially revert to this
> behaviour, but with one important distinction: report racing
> modifications, since lost bits due to non-atomicity are certainly
> possible.
> 
> Given the operations here only modify a single bit, assuming
> non-atomicity of the writer is sufficient may be reasonable for certain
> usage (and follows the permissible nature of the "assume plain writes
> atomic" rule). In other words:
> 
> 	1. We want non-atomic read-modify-write races to be reported;
> 	   this is accomplished by kcsan_check_read(), where any
> 	   concurrent write (atomic or not) will generate a report.
> 
> 	2. We do not want to report races with marked readers, but -do-
> 	   want to report races with unmarked readers; this is
> 	   accomplished by the instrument_write() ("assume atomic
> 	   write" with Kconfig option set).
> 

Is there any code in kernel using the above assumption (i.e.
non-atomicity of the writer is sufficient)? IOW, have you observed
anything bad (e.g. an anoying false positive) after applying the
read_write changes but without this patch?

Regards,
Boqun

> With the above rules, when KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected,
> it is hoped that KCSAN's reporting behaviour is better aligned with
> current expected permissible usage for non-atomic bitops.
> 
> Note that, a side-effect of not telling KCSAN that the accesses are
> read-writes, is that this information is not displayed in the access
> summary in the report. It is, however, visible in inline-expanded stack
> traces. For now, it does not make sense to introduce yet another special
> case to KCSAN's runtime, only to cater to the case here.
> 
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Will Deacon <will@kernel.org>
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: Daniel Axtens <dja@axtens.net>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: <linux-arch@vger.kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> ---
>  .../asm-generic/bitops/instrumented-non-atomic.h   | 30 +++++++++++++++++++---
>  1 file changed, 27 insertions(+), 3 deletions(-)
> 
> diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
> index f86234c..37363d5 100644
> --- a/include/asm-generic/bitops/instrumented-non-atomic.h
> +++ b/include/asm-generic/bitops/instrumented-non-atomic.h
> @@ -58,6 +58,30 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
>  	arch___change_bit(nr, addr);
>  }
>  
> +static inline void __instrument_read_write_bitop(long nr, volatile unsigned long *addr)
> +{
> +	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC)) {
> +		/*
> +		 * We treat non-atomic read-write bitops a little more special.
> +		 * Given the operations here only modify a single bit, assuming
> +		 * non-atomicity of the writer is sufficient may be reasonable
> +		 * for certain usage (and follows the permissible nature of the
> +		 * assume-plain-writes-atomic rule):
> +		 * 1. report read-modify-write races -> check read;
> +		 * 2. do not report races with marked readers, but do report
> +		 *    races with unmarked readers -> check "atomic" write.
> +		 */
> +		kcsan_check_read(addr + BIT_WORD(nr), sizeof(long));
> +		/*
> +		 * Use generic write instrumentation, in case other sanitizers
> +		 * or tools are enabled alongside KCSAN.
> +		 */
> +		instrument_write(addr + BIT_WORD(nr), sizeof(long));
> +	} else {
> +		instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
> +	}
> +}
> +
>  /**
>   * __test_and_set_bit - Set a bit and return its old value
>   * @nr: Bit to set
> @@ -68,7 +92,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
>   */
>  static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
>  {
> -	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
> +	__instrument_read_write_bitop(nr, addr);
>  	return arch___test_and_set_bit(nr, addr);
>  }
>  
> @@ -82,7 +106,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
>   */
>  static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
>  {
> -	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
> +	__instrument_read_write_bitop(nr, addr);
>  	return arch___test_and_clear_bit(nr, addr);
>  }
>  
> @@ -96,7 +120,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
>   */
>  static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
>  {
> -	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
> +	__instrument_read_write_bitop(nr, addr);
>  	return arch___test_and_change_bit(nr, addr);
>  }
>  
> -- 
> 2.9.5
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200902033006.GB49492%40debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net.
