Return-Path: <kasan-dev+bncBD66N3MZ6ALRB7GJXTWQKGQESRHN7CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 930E0E07D7
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 17:49:17 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id w8sf20387810iol.20
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 08:49:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571759356; cv=pass;
        d=google.com; s=arc-20160816;
        b=x3+w8IZDFePravfb+6OvpNyq+VBU2s8aorOyJCRGkjLvt629TzGAzpVuSTWQG1fg0f
         KFT+HcqTfdx1wf4Jw8//zJX+Vg8H29wC7wVxsjFMCyD4JWZ6e6OQJRb0QW+VaKoXeaRq
         4tvUXiQk7BVFkaESAiEgzuXGXbQ5miAiAmpjAyoB3iKoxVtcDcxuf3xB5ZotyNLMqUlW
         VUpt6jRe0LMzDnFpAur0WpiZpUvO944+pAhPrPMdBCzEeyn5KkWKGXEiTi99RZf6tqY2
         ZopdR6PJm4H7meMZQgkvqIUDGvqGhwhpVB26Ns1dIEa8WShDn0HDlMmd3+Fnv2olL5Vl
         fGJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:user-agent
         :in-reply-to:mime-version:references:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=KtRqVTZDL5OoZqvW0ESVJAWsxcDdCF2FFgvPveHbdc4=;
        b=m52WuSC8ZqRbJjBmyz1SlknZlgrhzKpWdXgfm0dl5f8HHcN2xY6zZvK+h5FHsEgqz0
         DXD4ElbAwy/QH/GMcgfw20Y03vi3nv7KCWd04Kh7B+iTVoGMrqS8BfxU9PM+dEwC7OeU
         umYNigEpB7KmBHmBtqo2GtsEAEgBoYVCrs4dAhHcLmDgZSHLWgpQz30oc+JyIB1ImGiB
         a3INopbvw+N3vN7PoIjrc/8+AWm/G3wSsIAvUnRzT8hZMquMfVlUexwKAt3F0MObChOm
         Ju7RtOGy1nWLNDkKr7mvv7F7HXIWRn9EEQR7itVC8Og4rG93VJLFH6uLGNzs0KdwoMrY
         D8Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JFZKBeNY;
       spf=pass (google.com: domain of oleg@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:user-agent:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KtRqVTZDL5OoZqvW0ESVJAWsxcDdCF2FFgvPveHbdc4=;
        b=aKM+/orulS8PI6LXfU3/X3H1+yOGgfQBpICbhFc6/BU+1ttxvRnNahDkKvIRe3kiuX
         YWXYJtRaY0Ii6YQwVjZLNbmQ/UyvgeqR2kjdERR2gKAWDc3mNRiB+8nCpzyIjbAKw12v
         CYJKiGNr/70N56+ODwqmt4iPBjeqy72CmPsUq3ZJSA1MdIJ8PFF31VKs/2WqpcrkwOEi
         EpkKLHL/gTA+QqCGN1PNQhA+NFylllFON+8gR3IR2LLDyf3INnnzW8LfQzrBpG0/u6wq
         glnIgyMTbogu/HXsfIXAe67Nu/ryggJTBexJ+cegy9lNBeV/iTthkAbB+46A3woauVqG
         Oxkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:user-agent:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KtRqVTZDL5OoZqvW0ESVJAWsxcDdCF2FFgvPveHbdc4=;
        b=K+Y+GmZkddbVvGBBgSRJ7m7AJl8GzDK8IOekIzBg6mu+KPvhd9xw939hIvQedB497q
         YIW96mWS7k3HAsYV1rRtwEfUjZTjwjoryBMgEe+NfKogne03+AJeS666QFeg+TmSfEsE
         LSH5Mk2x9D3Oiy/fJx8eMx6YGaVxxA8bqFPbMXYrxrkwLi2n3PMbZlBA8uR79YKOr8LV
         niojT6k7Y4QM+djT2Rj96Xjjag1AOMNGH1f3SEXp84XFFhPoWjbDfyhUbHbCsbKpEfpW
         hQHmtTY+3P0M4g3DhRjodtlw/b5+ceXhxVbuGr8t+TtY5pFvdINQ2Yrn6xX5M2H8aW5j
         /UEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVqdobE250xf3ZXmK04txtXrGBP8UsA8K9jJ0ULNaGeP2jgEiZN
	HZiUlXeAazG8yQV1VUR3qK8=
X-Google-Smtp-Source: APXvYqyyaA+J7IWMse6SvRVuiJteWrygWfM6CEN+7JIxTk9tmBF5GPnCP2brD7gNvVHFbzKKJunY3Q==
X-Received: by 2002:a92:d34e:: with SMTP id a14mr11226580ilh.289.1571759356145;
        Tue, 22 Oct 2019 08:49:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8707:: with SMTP id m7ls3821330ild.2.gmail; Tue, 22 Oct
 2019 08:49:15 -0700 (PDT)
X-Received: by 2002:a92:dd88:: with SMTP id g8mr33299781iln.109.1571759355722;
        Tue, 22 Oct 2019 08:49:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571759355; cv=none;
        d=google.com; s=arc-20160816;
        b=qHanF+LqRKYNhcwCpoZFjkBDhJg1NeCaiQTOytzys8DXlU/QLFAPHDheVY5RzG4Pcz
         ag70WyG35SpKVwA9PQbQtyt1UkPi4CgaYD9O8vnuxI4S49Fh7YCHTN/KJ/4a9Ciu7TG8
         4vLX9HcP97U1qrb4pWsfbKmuYp9IWwzntADsgIEysA9WZTMcY3jrZ9E1Y0eaDRXV4Uob
         dWh01DOAMwLrRKQl1SoKX4cDwyS2N14nwcXj98OxLyhShRgiwEvfQmnia38Cs1r01zbL
         QSN+jUCdR9x/znTeZMoUSoBcfFnRGxpyf/D+yinT1W/iasjLAOC9eXuilu7PDmmWQ7zH
         p1KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:content-transfer-encoding:user-agent
         :in-reply-to:mime-version:references:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=soPvBg70/+oC8uencQegA6z5y64aNbKflTrsxEmRfUE=;
        b=umixs33UDQtOopTJNv9xQdnu0a84d0hwC8tnTJ5JezC5V3jyYtrNZPmPJllNqeDvuP
         FXgKBYVWyHjEqPDPKsC80OJ02B0V+o3WsFoxoi6pHfn8utYcu/ubEoDZytuNbzzNQWHD
         5lNsSojXbG2gsq0z21iyoiFJtyyAvcHaSS7oFHqPxsd0NA+r28y1OyzKK2yK8UY+wdAS
         X7HOT81uo7tZ2GoamULfxZ/usQIXbHsjHhODBpbC8lekcFyZQkGRK+Q9UPOWpKCBayfZ
         pDa87Nsl0MaAxSeVn9rlVImqxiEncq35eWXVA1Xyx5G62nCobVMlyPCr5pj3r8bwdP4Y
         bckA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JFZKBeNY;
       spf=pass (google.com: domain of oleg@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id b12si1151834ile.2.2019.10.22.08.49.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Oct 2019 08:49:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-352-pP--3crAMhSTJdyaJUkLUQ-1; Tue, 22 Oct 2019 11:49:10 -0400
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.phx2.redhat.com [10.5.11.12])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 64FA5800D49;
	Tue, 22 Oct 2019 15:49:06 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.43.17.44])
	by smtp.corp.redhat.com (Postfix) with SMTP id 88EE560C57;
	Tue, 22 Oct 2019 15:48:59 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Tue, 22 Oct 2019 17:49:06 +0200 (CEST)
Date: Tue, 22 Oct 2019 17:48:58 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com,
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org,
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191022154858.GA13700@redhat.com>
References: <20191017141305.146193-1-elver@google.com>
 <20191017141305.146193-2-elver@google.com>
MIME-Version: 1.0
In-Reply-To: <20191017141305.146193-2-elver@google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.12
X-MC-Unique: pP--3crAMhSTJdyaJUkLUQ-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=JFZKBeNY;
       spf=pass (google.com: domain of oleg@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 10/17, Marco Elver wrote:
>
> +	/*
> +	 * Delay this thread, to increase probability of observing a racy
> +	 * conflicting access.
> +	 */
> +	udelay(get_delay());
> +
> +	/*
> +	 * Re-read value, and check if it is as expected; if not, we infer a
> +	 * racy access.
> +	 */
> +	switch (size) {
> +	case 1:
> +		is_expected = expect_value._1 == READ_ONCE(*(const u8 *)ptr);
> +		break;
> +	case 2:
> +		is_expected = expect_value._2 == READ_ONCE(*(const u16 *)ptr);
> +		break;
> +	case 4:
> +		is_expected = expect_value._4 == READ_ONCE(*(const u32 *)ptr);
> +		break;
> +	case 8:
> +		is_expected = expect_value._8 == READ_ONCE(*(const u64 *)ptr);
> +		break;
> +	default:
> +		break; /* ignore; we do not diff the values */
> +	}
> +
> +	/* Check if this access raced with another. */
> +	if (!remove_watchpoint(watchpoint)) {
> +		/*
> +		 * No need to increment 'race' counter, as the racing thread
> +		 * already did.
> +		 */
> +		kcsan_report(ptr, size, is_write, smp_processor_id(),
> +			     kcsan_report_race_setup);
> +	} else if (!is_expected) {
> +		/* Inferring a race, since the value should not have changed. */
> +		kcsan_counter_inc(kcsan_counter_races_unknown_origin);
> +#ifdef CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> +		kcsan_report(ptr, size, is_write, smp_processor_id(),
> +			     kcsan_report_race_unknown_origin);
> +#endif
> +	}

Not sure I understand this code...

Just for example. Suppose that task->state = TASK_UNINTERRUPTIBLE, this task
does __set_current_state(TASK_RUNNING), another CPU does wake_up_process(task)
which does the same UNINTERRUPTIBLE -> RUNNING transition.

Looks like, this is the "data race" according to kcsan?

Hmm. even the "if (!(p->state & state))" check in try_to_wake_up() can trigger
kcsan_report() ?

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191022154858.GA13700%40redhat.com.
