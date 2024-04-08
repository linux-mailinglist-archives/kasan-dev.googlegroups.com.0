Return-Path: <kasan-dev+bncBD66N3MZ6ALRBSPZ2CYAMGQEDGGITCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5964F89CBFC
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Apr 2024 20:51:56 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-7cc764c885bsf555856339f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Apr 2024 11:51:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712602314; cv=pass;
        d=google.com; s=arc-20160816;
        b=F2Fl8/ai1ecw/pGP7Vd8Hp006qSpvQXWKUCeBDtroxX7oidkjyGWD7abOWUanRr+/Q
         B8xWWvGYcT1C2JY6fd1maNhiq/lQiSdaYxBDSJ1qeC3e18YJCvcBDlmPl9+eDWNsm/H8
         GN/bZG/VRmsB3dLRBCYnchQpaJ3HW6Gr8g25NdzdIpz0WBP3q3iKwxu19YWkzBAzXXS4
         40GrXd2LGULGnRdFS16JHONk7aMsEwQFqE4P4G+0x5/YCZNiHRFSr+XuvQEQghlyXZcB
         BCfPlvJFnZjHn0lSEGr+o0Schh9NpQdhZy0IBkgY0fe26xJQ0pWF/uwVAo4+I8w7d4L8
         sI6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gGJByzy5zE6nJDxT2TsnMaaZbnDJr+QGSTwPvwrZOKg=;
        fh=xENUtT7OoHHbUTAZxeqk4ajjH6XjUQ63181LMfFh0pQ=;
        b=Xo0s4fnCT4m8SYE7cdhccmFeaPZ/sPZay73Qu0RsPPBYRJr1xR1SStk1W8Qbq7+26Y
         7sywoT89C7+iislQD8My86WrVSJL2Af+wb7HXNS4XrPdEUSB8lCkqh0KNZMgw2xkfNJl
         2YTrtM326TZKf1Le93+9KoCsPVWXI7Ix7AHoOtFR3+IDXZIHB3Tnu09qYTb5XgqZxdVN
         JE4hO7TPDaciB0rtxRFGrPS2yPqXS5GsYIlq9NPqZ62uy7RlHGvLdMBRz9TGaApnIZSJ
         3PcX/+Z3DyY6X/k9rlTqFKnYl8tYWP6q8+OB0jyh7zbubOHgRzoQibHdVzGf7306wEHS
         bRQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ROcE9ksP;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712602314; x=1713207114; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gGJByzy5zE6nJDxT2TsnMaaZbnDJr+QGSTwPvwrZOKg=;
        b=UyvsBvxPRA8mt1nw2k94WUx9bvXPapx4vQ77IimMLlt0QxyqjdG5nKqA0Tmd6IxRos
         KFqkSMU05Avv3w7PXwauaWunoI7qChvkI9bXIRRqbaTbAuz5nmq2s3bw3drITH1f/J/p
         fg+fwd3w2FabyJ2dYvVWpHqLBAUgtIZhScWOOXz8Yf2DnBqnAl6qwsN6+J9uyAVpuk3m
         lIJ8C4K6MXwTkiYHWmwvIPFKVoHm7Q6wnhURrScLCKQFrjgjmlx700Ug1YzCbK+R3pvw
         J7xKeifWXbXFEOdlJE+ZhM/2eRwWeSyb8imtvh2ohezWs7lYZPAQgGXxSXVGf9A1UYKN
         Vnmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712602314; x=1713207114;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=gGJByzy5zE6nJDxT2TsnMaaZbnDJr+QGSTwPvwrZOKg=;
        b=V6dC1RwWfdyyWgxEy/j7zlRaFuEhMDkfWS2cowfzNCarVIY7TOdah0+JOBNsL24Ufh
         SLvcTBqXWkfKc1l8Yfvu4JBngZf4ye9nnMIdUDLX6BXMQQ+tuBObK8IFaEMKnVbVbT5U
         cnd6KubFMrY3Z1wDXxRzg8zK1izYVWaN8W8S/m6YER4uJcofyLxtQBTHG41Vh4hku34Z
         c5u8si1FslKHg42odbc3NZSTKUrLsnQ4l5jx6az5YSzL82aVUjkajZqy9bwAJCe3v6HQ
         JFSpUOZukLa8LLGzhCqfegpKDu6ZMEywPHEzSh42XNN73edhLH3Gz+kQEqHMquifcF2r
         HT3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlGjhArfFlsvFKS7OMQ579KdO2eOxLxnYlf2W0El6o3yojfVLbmcRW9N2t1GclYudUYsfUEUM12gSEJw5ishKJs2RFa1+mAw==
X-Gm-Message-State: AOJu0YyOLog2LuKJn8RF1efA8SCO8dCBMt87vav8zA+lF+JegVLTJQBg
	NtWi3s6fkUNctR6a6MSZkDn32E/pZ7XH/XaIjTZRLWRD+25HlngR
X-Google-Smtp-Source: AGHT+IHRfVGg30mzUL7YKNOujUSiVfCCvll2KSBqPouAOymznz4dTGJeBL4uWMJQLdVZEf+PrupLhw==
X-Received: by 2002:a05:6e02:15c5:b0:369:c0a3:2ad7 with SMTP id q5-20020a056e0215c500b00369c0a32ad7mr11208739ilu.12.1712602314084;
        Mon, 08 Apr 2024 11:51:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c152:0:b0:36a:1ede:b31f with SMTP id b18-20020a92c152000000b0036a1edeb31fls1003537ilh.1.-pod-prod-03-us;
 Mon, 08 Apr 2024 11:51:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgOGx1WlspH7YODWqNLwy6zCshYh7smxYHcK2+p1IsH675B4fSaXSYVpQTR7aZifFig1A8AFUj919QoT6a9pISlnqg5Faece8c7A==
X-Received: by 2002:a05:6602:3e83:b0:7d5:e9ed:efb4 with SMTP id el3-20020a0566023e8300b007d5e9edefb4mr5050155iob.10.1712602311648;
        Mon, 08 Apr 2024 11:51:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712602311; cv=none;
        d=google.com; s=arc-20160816;
        b=j2kzWgGl6B0JDR0II5stQuaM2PLt2jXVEORnWHQZIz9LBxijJvWhgue3y42vZ+R368
         o8D/6hby57syO97queK9vH2X/JlRl8ylg9tUEt3ZPkCgHYpp3E5I4AejtNGKLFZzYgYA
         uizOZVTmGbbSXD5UxasH5GpPpUkuNJjH04N9cqdO5bkaOiNIDhOmbCE3m9KS1xdVoyZh
         TfzgB4YidYPwgBougLAT98GaFqQAcxWIvmUcVeGj7qihc8EXQxTAgkdNvhuGIpSzJSil
         TiQXCJuAJuniJxwjgkxF/Vco4C5ZJUNflukrudrvIhuqj2vJMl/RhrU+LzH7Hekr2xeJ
         YJ6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Q8dFnN+DVwM1sWsRYbzV9b0Y7Yoo7FUCyFFFRTCNFqQ=;
        fh=zru9GisBudL6wscQvdg0j2VNCYgIpM0w/4ZvPY1SZGc=;
        b=gdi0jDOPhTbOpgXlc2eXirhgm2vyASZBmo+X9zFI/rrGINaD3beIR4woNIuaxpRO6e
         bfoiCMFcLzmgROJzt5I04HJ7v2UpMvPVt17suzFPwIyn04fBHk+7JozRfznVRt1+D6mC
         tucizq1O6aNe2Ofu1qxNSFpb1NS0Iu+s7z7f8oy7ODW6Hf6VD/Ud4FfuS1/4NM2WviwH
         IEK9B3I8U1ZShes5xMcyCscN48YuEOmUupiZGCcVTdhamyRBajOuyMruPxpn/0QfYM8D
         GozecZrvGY57znxa8K+8n9rZzopDi8riDiWLtERunA6mcGolJYMMuQxVeeq/aPhGvM76
         BJWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ROcE9ksP;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id k18-20020a02ccd2000000b004828e9c489fsi201313jaq.3.2024.04.08.11.51.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Apr 2024 11:51:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-537-aQW-xCk8MX2eTz_blcr48A-1; Mon, 08 Apr 2024 14:51:47 -0400
X-MC-Unique: aQW-xCk8MX2eTz_blcr48A-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.rdu2.redhat.com [10.11.54.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id BE1D1802CA7;
	Mon,  8 Apr 2024 18:51:46 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.226.180])
	by smtp.corp.redhat.com (Postfix) with SMTP id DD1B3489;
	Mon,  8 Apr 2024 18:51:43 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Mon,  8 Apr 2024 20:50:21 +0200 (CEST)
Date: Mon, 8 Apr 2024 20:49:57 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>,
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
Message-ID: <20240408184957.GD25058@redhat.com>
References: <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240408102639.GA25058@redhat.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.1
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ROcE9ksP;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
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

On 04/08, Oleg Nesterov wrote:
>
> On 04/08, Dmitry Vyukov wrote:
> >
> > >
> > >         if (ctd_failed)
> > >                 ksft_test_result_skip("No signal distribution. Assuming old kernel\n");
> >
> > Shouldn't the test fail here? The goal of a test is to fail when
> > things don't work.
>
> I've copied this from the previous patch from Thomas, I am fine
> either way.
>
> > I don't see any other ksft_test_result_fail() calls, and it does not
> > look that the test will hang on incorrect distribution.
>
> Yes, it should never hang.

Forgot to say...

To me this test should simply do

	ksft_test_result(!ctd_failed, "check signal distribution\n");
	return 0;

but I am not familiar with tools/testing/selftests/ and I am not sure
I understand the last email from Thomas.

I agree with whatever you and Thomas decide.

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240408184957.GD25058%40redhat.com.
