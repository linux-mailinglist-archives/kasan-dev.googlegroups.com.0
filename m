Return-Path: <kasan-dev+bncBD66N3MZ6ALRBQ4O4CYAMGQEWEUZQMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 830818A191B
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 17:52:37 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-36a36c04ab4sf28631165ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 08:52:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712850756; cv=pass;
        d=google.com; s=arc-20160816;
        b=j5j3Xk8NCa1EDRnFuDoaM/tGG2Oi5R7SI5Bx6PaKnnkRZ77UGfbZSzHQ/JDL3CzRoY
         RXHReB/71fVLxpEwdiQxIaS2ZyljDhLEs6M8voSIfAD+HF2Bk7R/xG4IApXgjj2YWjBw
         52iHGWuczAt2NaSFMAfibmPbcO0w/X4vCFxFZhCl9H+DJrxhhDOcLemp6WlAjLGAfIIb
         CJcueD8sFxtX3E9Zj0JYPds+Lj9+0sH7HN2jynPkHQpOcpbbbHF5AAIQ6WduvwilBLOk
         VPCzS86Mcg9g5iU35iqrzDNeuM7W13oPG7TFh7VJH6Zudw97gRr1yKCKo7yqVNk4oxnW
         I11A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=VbCi+DQVsLAONouHOHZEvTLxNrEhJLmNrQNlVAq0wbM=;
        fh=n0vc5jdLZKOU4rB6RvQhdi6xx3jWS8L43ZWMo8fPUzI=;
        b=puu+Wl7rkAC5PuKaTq/s4kaPe3IfzwTqmn3v37RDiS+ghwkcAcMNgA4+DFten/UiBo
         cyWWklm83r71gt/K2pnZRoAM1dqVQAf8RF93A5tdjlIIy36m2C5EwTsIuOiNRG/w+lzs
         I1G/56e2sDbINbKru1cs1q9gv+Kuh58Bg/XdoxGk/fi+bTRYzfBXKA2ErlC9x5IH61Ey
         SfdbvFx/fd5A9NYz8bOimcJCrPXiWoFOKtBKZRUMzr0zoZ3suUT0TxFMGQOxwKbL02sI
         l1qwzXtPQ88ETqotvqMKTz613M0SyEvlLK/RoAmgjnBCtqHUC8uy/VDSFKT8CLNvUGGm
         RCig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XB6KcHOR;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712850756; x=1713455556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VbCi+DQVsLAONouHOHZEvTLxNrEhJLmNrQNlVAq0wbM=;
        b=Ty+/IJUP0qzk1geAb5e7U6Or8Tqkz1oTX+v8HMBDHMVFbSw+DyPXs6xwa8xLigzbEk
         viuJkCF9XIdrVLI0ZnySDcF+4NPXqeoCR+C3y036vhlGlLBSPxvDXuawIWMT2bEFYC6L
         zCYqibbXgjq45swKFfUJSccia8smCnLyPcfRP1aGXTXAnQKsgfcnnCqxW+bckeWmgZ0G
         gRyesq1vaN13lmHQ5sb02sS5SVRmgJY2Mz3SlDdbeLtU8EP2cPyfX4LRsgQ6TEn2v9uO
         ogWXorY5OdT23Of6JFRfKkLmKntndTYxMGtbtm45h20wp8nXVSCDOM3VPbe/7dV8MV3R
         3zmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712850756; x=1713455556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=VbCi+DQVsLAONouHOHZEvTLxNrEhJLmNrQNlVAq0wbM=;
        b=gf+hOCYLqQj8pMT9U3fnbgEEntRmW4sqWjq/CnygPRT8ZklM+ZEIOqS2X60swOCztU
         PXP93VeXaEEugssE4Qu/Xv65PJd/fwspyCZB2oyrCoT950y0AEHBtnWVLygI3iE8MyG0
         BHm+7QncQthEaEUHS0UE3M/jG9r0sV5XUuJrrE1GZjHFl7xVY2T68A9z46OhMbIBqPMl
         SWy/6atVMJU6g9PaJ+opwy/6CjE/ArB/wfZwM3rZugj7h0XqLgFPvTHYsff7DBhW8aUp
         KLBCLSh0r0Ohz6LebIa6Ka863b3FPyXvvxLE6wXrx6ESqdHEtg28AaRl8VTU8xEjGoq2
         RiUw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXo19M5THDE3MiE3u/7o3tf0W2bS68WUtS7LcUyEYtWDQDnJXLAFLw0YJfr4hTcgOfUQ7lFAYyNgRzodV5n43svjTt0iIzFSw==
X-Gm-Message-State: AOJu0YxGFvlgRHhT5bWLP12w8DiFwfNv7ijgvzd0Y0OL2MDJjmdQMrun
	+4qlOEKIIaX7HduRwBjTTZ7PTZfxufODI+hOFcf/R6V5QPzFvxfx
X-Google-Smtp-Source: AGHT+IEOMxg9brrSLFb6s3hkAGioxt2GtrQn0QRM5TRWUWkp/y/dlrCzmIEQZrBWV1hzXeYbFU0laQ==
X-Received: by 2002:a05:6e02:1568:b0:36a:1251:7a21 with SMTP id k8-20020a056e02156800b0036a12517a21mr7159880ilu.19.1712850756038;
        Thu, 11 Apr 2024 08:52:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6606:0:b0:36a:31de:f282 with SMTP id a6-20020a926606000000b0036a31def282ls24555ilc.1.-pod-prod-01-us;
 Thu, 11 Apr 2024 08:52:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrbvdaCvkB6W45Ynil3J2rz3LWXFM6erMDchZfDCs2EShEHEsH0ial/cUq/Vc1n6AMYUv+vdgVBrAWGYS3ItMC57mOfPgTD4tVbA==
X-Received: by 2002:a05:6e02:1aa3:b0:36a:297d:3f0b with SMTP id l3-20020a056e021aa300b0036a297d3f0bmr7235201ilv.15.1712850755027;
        Thu, 11 Apr 2024 08:52:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712850754; cv=none;
        d=google.com; s=arc-20160816;
        b=cG4q3sBhIUFKs4OgksWbZF5H7OCBRwp36c9x1IZSx5yhwyxTWPqmCw3ii0tLG9y0mg
         XmqPQpduYwHQilEg3kehR+prtcLCa7WyOvjOlkSQ7+NJCdCnBtDpcAdqRMeWbEvtbmuF
         K/zwOcT351J5fbC8VqtVcJ41FEcizDflBr0jhu3xCRY4D7oz43iEA/Q5m30AiKyyFjXc
         NCZu+0IKOkzdgVQPNzo8bxX7hqR/l6Ni+uZn6kkvdJf2rrx06C9MTD6iOK3i4D9fBXW1
         m/T/lw9/LD/Kp/Flpr2vIR7ORc/DZ3MqXS5Lyf5nz8kA3hePRXdG/nAe/F5Yq8zdVlgu
         4aRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QCBZYuEx8E6Ilt7WeXhmEcjbf72dLVjaYQUFG/SF9i0=;
        fh=aQEkf5Ok4MWqvcHARagZ5SyuALV1QK8XYtt7dTU1hfU=;
        b=SWcMtl9I5/MB7QBIRqyA6GDGOQGeW8x+jT9DEtLppR2MEEm68oSUIpKFAwZrIP9OEf
         fx3QaEv2vsju23LVpFvq+J0a63wabqpWyueKS/AB9yj040hrNmn4b577+HZXg1txuKOA
         hIjSjDoDFBZJJhOOuFidI+MwOgiF8tBcDqj3I1tp6DRJTk0lf74zSDEMHhgB+9xp0e5/
         jAHwsl3mI+WJE8Z4d+5H8HzMZPxvB89GxlnoUh3DWd/C7iU+7VVtkyQipemj12McUANC
         +vph0EwepLaidQR5ZrbH6DYiVHdgiZb7rVL6x4jD+jr7yTBTPJ/ODo7ri+udzuErF5oa
         5zhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XB6KcHOR;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id g6-20020a92c7c6000000b00368b3f7f8b8si114865ilk.3.2024.04.11.08.52.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Apr 2024 08:52:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-264-0IQtr4SfPViOJ6MMcKm6dw-1; Thu,
 11 Apr 2024 11:52:28 -0400
X-MC-Unique: 0IQtr4SfPViOJ6MMcKm6dw-1
Received: from smtp.corp.redhat.com (int-mx06.intmail.prod.int.rdu2.redhat.com [10.11.54.6])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id D84DD1E441CD;
	Thu, 11 Apr 2024 15:52:27 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.225.235])
	by smtp.corp.redhat.com (Postfix) with SMTP id BCF632166B34;
	Thu, 11 Apr 2024 15:52:24 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Thu, 11 Apr 2024 17:51:01 +0200 (CEST)
Date: Thu, 11 Apr 2024 17:50:53 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Mark Brown <broonie@kernel.org>, John Stultz <jstultz@google.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <20240411155053.GD5494@redhat.com>
References: <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
 <87il0o0yrc.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87il0o0yrc.ffs@tglx>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.6
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=XB6KcHOR;
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

On 04/11, Thomas Gleixner wrote:
>
> On Thu, Apr 11 2024 at 13:44, Mark Brown wrote:
> >
> > Further to my previous mail it's also broken the arm64 selftest builds,
> > they use kselftest.h with nolibc in order to test low level
> > functionality mainly used by libc implementations and nolibc doesn't
> > implement uname():
> >
> > In file included from za-fork.c:12:
> > ../../kselftest.h:433:17: error: variable has incomplete type 'struct utsname'
> >         struct utsname info;
> >                        ^
> > ../../kselftest.h:433:9: note: forward declaration of 'struct utsname'
> >         struct utsname info;
> >                ^
> > ../../kselftest.h:435:6: error: call to undeclared function 'uname'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
> >         if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
> >             ^
> > ../../kselftest.h:435:22: error: call to undeclared function 'sscanf'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
> >         if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
>
> Grrr. Let me stare at this.

Damn ;)

Can't we just turn ksft_min_kernel_version() into

	static inline int ksft_min_kernel_version(unsigned int min_major,
						  unsigned int min_minor)
	{
	#ifdef NOLIBC
		return -1;
	#else
		unsigned int major, minor;
		struct utsname info;

		if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
		       ksft_exit_fail_msg("Can't parse kernel version\n");

		return major > min_major || (major == min_major && minor >= min_minor);
	#endif
	}

?

Not sure what should check_timer_distribution() do in this case, to me
ksft_test_result_fail() is fine.

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240411155053.GD5494%40redhat.com.
