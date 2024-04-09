Return-Path: <kasan-dev+bncBD66N3MZ6ALRBMOF2SYAMGQEKSUKSNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id EB9F489D7A8
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Apr 2024 13:12:50 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-36a201729cfsf23511685ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Apr 2024 04:12:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712661169; cv=pass;
        d=google.com; s=arc-20160816;
        b=shvoFWQB8G2tv07cBMar/ivhtj+He+MNwH5BtMwknOk/k+P5Qoy/GofdBTaK+uudOK
         nStdkfHxvtoO9Pyl3aD84ospwIBQJ290IEsHT5UOlwG2MG+l1KuzSqn3VG4BF+Hhdw0d
         0Ij4YzbePGoPfjFGxV2x1iOOZsJFCYPlVWNV66ccctkWCX/BxOVgr95DRGYMXDXcIXqs
         TinWpE9M9quPd10DrksFK5YEyIkk/PHZGfDDyYfyMcOKOKlL8dvDn8oXy/pNEh0fxCZp
         nUIzcDwnzDpdvrbO/x64zClGdCQE9RGYgJSrit0abg6kEBEIh9kf6CF+9AwaqbGskcrz
         jasA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FDYavdZos2SBfSAXOPSX5UJhlLHDR1m49oIiMZJ8jME=;
        fh=rjgbifCWYyHlJ2KtDAHp6+SDwAaLsp0Nd0a4fhWIJaI=;
        b=F/s2pcu5yk8+/p4e1gY9WxBVOx6rFItN1bUTcNpEkW21DTpKaxI2yq1Fb2M1nkaqb+
         Efu4oqcWNkvYoXnxElWfTjXHeI0gmf++heh5aj6kg2eZ/Mge44IFvt++54fEFHibPtdL
         2MtddPyZhXlYM2fJKoi4NpLoB9EiUbsws1n0zb2EEXxu2RhFGEmwZc23YxbeM8WBAZb6
         seos8kBDZ+r3NrGV4ETXz0JHmJIZHyJEs+UdNrZn5cMx7gfIrZqHa9NOPv46uN2PiU2e
         n6VMl6qmOxZOU9Ac2DeCujwt/LeqeL8q5i62ML9cnufC1Bq/bTkI9ThcSfbm/wreR2Jj
         83VQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bvZSwTIR;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712661169; x=1713265969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FDYavdZos2SBfSAXOPSX5UJhlLHDR1m49oIiMZJ8jME=;
        b=q50ByPjSqupRRywbMnIv9FaY6Zgx1vmkafpxWQ6jfj3wYCEm/7b7rF7uFf5D3gJLPI
         s95ToH66/R4+OmmI8ddt/2eYIWi8dawvdF1Tl69GlBN5Qtj4Q84zpzXRbmSlP9ARgyre
         JYgXMWIJaFfCciP4TSta5PebX/3JA+HSrPX4EhixUoKkKMf70VFipnfUTj/9icvBOl8Z
         mQv14h4/uOnZetCOkrybPPvOKMCyWRu7P6eOZ0VV+39DZLZfmWGLF28j0HEIAZwomLgm
         L28KnBSbD0Iyr/CnExegZcjNjql/1NahQUf2vd46dRjI+2ZeRXNwYt9ATuQNJC26Mbdq
         DmGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712661169; x=1713265969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=FDYavdZos2SBfSAXOPSX5UJhlLHDR1m49oIiMZJ8jME=;
        b=LRyoOcqo+VRlLkcTrOAOmmaV3m2qoleZOzv2e6cAGqbL8OEKRvwBVDFaRxQBChH5tc
         dNq/31OdlAMZYrhCf3lsFj38+sUtQ84qsPeRfSPL87RTcVz1NtbrTnm2e7SN8dfGXH0l
         s5TDZix6Zuo8G5eAp1onFS/gHcpqFm6GAJUCbNEtfRtDNT2orWKI+YMCobOkmhztiRW9
         tIZtDdExuh7Ow1tJLOJiqWu/f+Se1//BfDQGjs7jEWS2EUw2TBP5LKG03A/8BK2qcOrj
         5XLMT/d7zWXYSq6BjUxY6INLEYLRjQC3cNricKcVFN/5h+3acAhSU0D3gnGaSC9TSEbn
         LOeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRGaXq30m3yN4FQmhgs6Ek51AwK0bXkE14xgxEKx/ctWa9YIIsrl7gz+mIErvt5DqcHjfn3lKFPTvCTc4vDwiINGKMMgjFIA==
X-Gm-Message-State: AOJu0YyoqqZeNW6bJrAUfDtkC9LxHMrwAY7YzL8Jq7DZWFPfyqXUgtwx
	kw+H0bFT7w5ILRQ/irUH/oVfg850m3fiw+S5RSYXKzENH/hOitcA
X-Google-Smtp-Source: AGHT+IEDG1pT/dw2Hg+7dbxQ1B7KEOXhIB1nUngs9wk0DPoq/Hx2dMJ2LrAX/9kji7O4eC8jm0WuZg==
X-Received: by 2002:a05:6e02:1a69:b0:36a:686:bc98 with SMTP id w9-20020a056e021a6900b0036a0686bc98mr13794139ilv.14.1712661169508;
        Tue, 09 Apr 2024 04:12:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:339b:b0:368:7cd7:c115 with SMTP id
 bn27-20020a056e02339b00b003687cd7c115ls1470495ilb.1.-pod-prod-07-us; Tue, 09
 Apr 2024 04:12:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0CNOSyFU8QhcUWaulk1vbbyi2hEQXPq/J492j/N/89Iu9sXNoWradIDk79r+NuTAvoppEVYf/PnirEIRC9CC2tchhbb78Xkx8vw==
X-Received: by 2002:a05:6602:4f8b:b0:7d0:966f:556e with SMTP id gr11-20020a0566024f8b00b007d0966f556emr12110284iob.12.1712661168495;
        Tue, 09 Apr 2024 04:12:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712661168; cv=none;
        d=google.com; s=arc-20160816;
        b=u0d2b1gehkndTpa3Op4GVa54i9xQy/TCah5mm+doWi0Ja+TTHLz1cYORiQhR6+Prjt
         XCV+BG7jrhYu4aHmVhBfjU82UN1dihtVFaI2UB28JuKfBWFG20xdP+3n+NDr2CBfo0aS
         2k18VvabeNtDwA9fMnxqYAyZc0+JdcpYIw8QXoKfsiEaJHbD2kkz6VuenoP1w0ghN05V
         v+x2qAintZFA0zUxKp7GaFs7ZZ5J1zXGFwvzlhIKfflQGM6NwgLkhdgjGKmKVx1aEaiy
         A1gQTSo9K5ooHIjViKPwghGIaT/fjWvmig8TIgSZrMREiVX2fTGNzlVY68h6XxyPBBu0
         nGzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WHx3oMFq8PtDxKa6+YzeOhtGXt27WMV38UwSpfqK1lA=;
        fh=ct+SAC++KuMnHEs0TDY7BoMNklHQXTXWPHBS4yDpdlg=;
        b=0YkIjxdSwDzUIYAxcYbSglQ7NmQBvkY+//0xKKeRxMDYXqxKPfA0DKIEWPP2GPHCWE
         EQBaiRCsgcoGDxcjy3578E+vOi71jfnKyVfnDtNnUMsuGg8GWR9cqMWEG6hny+rDe2Le
         sLXRg67Y9ddrXnFr4AXXvD0JbtZ87l1uwtb5SKUoQ+b/sdFgiFP3R/6QqwXsgsndcFGt
         y+tq4PBESw24w3/Ss94SiVy1HUhRtqI+6kRkwnyY5hRvXC/xBxAHU7+p/GZBlarJiZne
         R4IuSFx+nBtZk7gXmIc2DUgXcwLVwDplZJyb3lt/dbOUDKti8mnwQZ/zgjykNZBnmpWX
         A6HQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bvZSwTIR;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e15-20020a02a50f000000b004827c66cfa1si450088jam.6.2024.04.09.04.12.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Apr 2024 04:12:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-640-KwcDvaYCNkWlpBEde6-CnA-1; Tue, 09 Apr 2024 07:12:42 -0400
X-MC-Unique: KwcDvaYCNkWlpBEde6-CnA-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id A4135104B502;
	Tue,  9 Apr 2024 11:12:41 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.56])
	by smtp.corp.redhat.com (Postfix) with SMTP id 8D73647F;
	Tue,  9 Apr 2024 11:12:38 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Tue,  9 Apr 2024 13:11:15 +0200 (CEST)
Date: Tue, 9 Apr 2024 13:10:52 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, John Stultz <jstultz@google.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <20240409111051.GB29396@redhat.com>
References: <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com>
 <20240408184957.GD25058@redhat.com>
 <87il0r7b4k.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87il0r7b4k.ffs@tglx>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bvZSwTIR;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
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

On 04/09, Thomas Gleixner wrote:
>
> The discussion started about running new tests on older kernels. As this
> is a feature and not a bug fix that obviously fails on older kernels.

OK, I see... please see below.

> So something like the uncompiled below should work.

Hmm... this patch doesn't apply to Linus's tree...

It seems that this is because in your tree check_timer_distribution() does

	if (timer_delete(id)) {
		ksft_perror("Can't delete timer");
		return 0;
	}

while in Linus's tree it returns -1 if timer_delete() fails. Nevermind.

Thomas, I am almost shy to continue this discussion and waste your time ;)
But ...

> +static bool check_kernel_version(unsigned int min_major, unsigned int min_minor)
> +{
> +	unsigned int major, minor;
> +	struct utsname info;
> +
> +	uname(&info);
> +	if (sscanf(info.release, "%u.%u.", &major, &minor) != 2)
> +		ksft_exit_fail();
> +	return major > min_major || (major == min_major && minor >= min_minor);
> +}

this looks useful regardless. Perhaps it should be moved into
tools/testing/selftests/kselftest.h as ksft_ck_kernel_version() ?

> +static int check_timer_distribution(void)
> +{
> +	const char *errmsg;
> +
> +	if (!check_kernel_version(6, 3)) {
> +		ksft_test_result_skip("check signal distribution (old kernel)\n");
>  		return 0;

...

> +	ksft_test_result(!ctd_failed, "check signal distribution\n");

Perhaps

	if (!ctd_failed)
		ksft_test_result_pass("check signal distribution\n");
	else if (check_kernel_version(6, 3))
		ksft_test_result_fail("check signal distribution\n");
	else
		ksft_test_result_skip("check signal distribution (old kernel)\n");

makes more sense?

This way it can be used on the older kernels with bcb7ee79029d backported.

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240409111051.GB29396%40redhat.com.
