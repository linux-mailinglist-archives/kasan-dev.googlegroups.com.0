Return-Path: <kasan-dev+bncBDAMN6NI5EERBY642SYAMGQEFOR72JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id F3F5689D8BB
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Apr 2024 14:02:45 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5175737fe57sf1892e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Apr 2024 05:02:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712664165; cv=pass;
        d=google.com; s=arc-20160816;
        b=Idi6CR6E5vOYbsPZOJpyF5SOEnIIJMAhLlpS2wtJh5FnhDksFO8bR6NcYvmPAN07+s
         ruD/GILYU/tOSbQCDQv1GUTLodZfCx0KRCZtnGapjbfU0Yqy5pbU7758B9r4KAJqEKNf
         AqMlInIveeMybJNQLEySnJs0clZwlTuUfO9Dz8LKVStup6Gy8buLTuflzQhuckgS38kZ
         4SQNrJTa8QBmtqxI8J+I2E9oJq0eL/t/hhjISrinhCuM8XzRwnAuBE+y5U0bGjpeTLDp
         pyoklp22q2pczyHVCHpwNbly83p68p9l7qvSruRy+TF1gvAyFJW8uaJsfo/fK/AsN2BV
         CZoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=0YeGwD5QFBYca02cp2F3doXYPtDEvpJkNl81AdJ/G8g=;
        fh=9IWtWftv1e/fVMtSxee+dycOtqA1SD0sfoWfcVe2jwI=;
        b=qIqa5Vd+h4easfIUR9KsDe2/O6YXpqhFt6VBQTNYlmtd0LRU3Fb8CAczoATRSd3YLl
         djWXBaenc4Vv23NNYViwXrMQ5Md8eI0q8hyE1CXkHLMcKosW8HTg48LVVG5gbfbt3Npq
         L5JOOvxGQvktt/aEtylERH62kzCGjgKRBiotj7jwhFOHHIrXMU4lKTwSxhiqI0ogqPmU
         nVdQ/5GdboLMBb7FMV2i0mZmzLKjix8wn+6pgUUa3E+UxLdQ5oKNqXvr7dGRx3h45V8p
         dG9mrru6QxRjr19rIoRjRW1ZudwNzaXrvpyiYqRcp9ptW0XgRWm4zbfYjU+F55ElxsXR
         +L1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=UNuLPP5S;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712664165; x=1713268965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0YeGwD5QFBYca02cp2F3doXYPtDEvpJkNl81AdJ/G8g=;
        b=ZAUyv+CaS7SIZQTM6UY/PkOI5AndLr91JBNAFDIKWqeMShmGgW4tsKFtZDAOVaMqdm
         SMCSwBkPrkFWCR66+CA7P2GahBSMAKGqoPrvTsRCa3TGQ60NZpCeziidOpQLCquy5hT6
         ybt+Hz/6ms9m9AifmTMId8Q/nkqlUXNyLqywpYF+kcgA1oWrMurWn4As2vpom+cRTgiA
         QtYhDyUgrDw3D/rmTzhk+aJrVg8hHnn0zxR6YE7BUVf9hoyDeeZpivVMUL5/iwk0TbQi
         /eRxBBHzdrWfV8HF7QVLRsCL2+SI4GT7uFVFdqzugDRdDWLp9Ox3oOagrUNDhsCVLg32
         2Vug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712664165; x=1713268965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0YeGwD5QFBYca02cp2F3doXYPtDEvpJkNl81AdJ/G8g=;
        b=rZTL/UAdwH+oWXLeiTjD58yPC7rhKt1idGA8MEkZwej+/pobeuHqx6Ieg1mGYj3bRB
         GE5gnVS60xUI/nB8bzZKvjLfVvzJHzi4YhIiQZH+CR992xYnUqPzGX58Y+TyB7fBwH1M
         6MP2u5K6I7A7IYztWBMaoxJWBUb+wLx05n1DV3JHIZMlO6zu/j4Wf/r78fQaQYgVYO2b
         fUoVLnMsQZ3mwbo0IKI0xEii6bVj3O8y+y1WGEK7k1WhfXSe3C6epnreXU2a01d4nhEs
         rxWjaGhk3ck41nYCvVLlH96BJg1G2dq4X7gUR41NyyMYyyAWPLOA8ImhiFnIIgTRZIvm
         duvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrFasq7DW8UxKhvWEquOWLY44FpmhVcFvUgRGl/1f7+zhtdxeO8AYKk9N62JByRFN145txxWUe79PYgGjdjZYCJCEJYIK7nA==
X-Gm-Message-State: AOJu0YxyAINiPZAtTR8gB0OcISgl8MKWDSuUblEaJ1R1tqfqZ/vAgsXE
	03EClpjjKUihdTLsC5kAKdPfaPuSHTtBzGbQVnQ5lOE5KiBwK7y1
X-Google-Smtp-Source: AGHT+IGBaIgO3yoB8hSfVgsoqubwmHy3eHDr+QIRdr4w64FfcXNz0t2D/ohKrVb30zeuGB+ufZTmlw==
X-Received: by 2002:ac2:4c38:0:b0:516:d099:400a with SMTP id u24-20020ac24c38000000b00516d099400amr97771lfq.0.1712664164122;
        Tue, 09 Apr 2024 05:02:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3604:0:b0:2d4:369e:7edf with SMTP id d4-20020a2e3604000000b002d4369e7edfls124748lja.0.-pod-prod-01-eu;
 Tue, 09 Apr 2024 05:02:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXRSGqpEnwg10qBDNTi2dQd1hZak+briiLqDHt111TovWugH68+G5dnhsLnC6bvUtlDjdFymsllpis8Syyv9oPTuGJn23QMHr3X9w==
X-Received: by 2002:a2e:bc1a:0:b0:2d8:901f:7f4b with SMTP id b26-20020a2ebc1a000000b002d8901f7f4bmr4701844ljf.5.1712664162068;
        Tue, 09 Apr 2024 05:02:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712664162; cv=none;
        d=google.com; s=arc-20160816;
        b=zbDhbg0JApeVq9SrpxunxjYCPdCUCvvt2VJyC8zPFVuJ3U5ICGzMLY9u6sq79nnWVF
         p6UAcOfM/B64DayY2ykHjFrf94UstWFLxwrtpdhgTyRhIlQ3YQiQPlmi1ghLvKpOQSus
         gyYRt5hqXTsYJHEUZ/nxQ+gi8MDK3jXwP+4fwxpF2amHgabvkDA5zceb1I6HuYJblTEH
         vqemO93eyJBJw3uAD6ttSlxNvCY5NZYwfTXtGrBaHeSONSt7pYtOogvOkjMo4x0M2Fpd
         ZiuPWUBTgSIw8gdmRhmvH5Okq4CdgvNKsv7juAqS7RbK6q5TYWDebGwUIgyUrOuUPTI4
         FiCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=8NoF74+Dpoxqa48kWnxI0CEBaofoHHeQ96U8jZayGGY=;
        fh=YMfigdof9h68/hROUTb3YhceEFrPPzqQv5CTEIAfxPI=;
        b=x9KHGCMp6mi+Vfp/wFuxjW+l2j8ra0hc754cb9PWkjHrAuJOO9BiIl85RFLpWyGct/
         yECwXzwZCXxuRv4014UMlu/l2FM+YV7qfXKvnI3Mib/Gng58l7QHtxJCvHPLRWZTMtQ3
         h+uAGLZfbldpdeFomhgd9qtEXBQynSCUt0C+C0WDp9269NudntA6QV4MFxdqQV050DBC
         Y1jxY6kExfb9K7YJGQ4jaLofpFF8hUySbsYteRXDFQvfRV6pG5o5Zny0kkLTns2ZF8wg
         VPiiQyVadDJEQnCzigQItckHLC9u3YvT8BTOD7JB+bjU0UxD+n7aOAjZzqSL1oR43yDD
         9hKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=UNuLPP5S;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id b3-20020a2e9883000000b002d85301f1dfsi247845ljj.2.2024.04.09.05.02.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Apr 2024 05:02:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Oleg Nesterov <oleg@redhat.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, John Stultz <jstultz@google.com>,
 Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Ingo Molnar <mingo@kernel.org>, "Eric W. Biederman"
 <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, Edward Liaw
 <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
In-Reply-To: <20240409111051.GB29396@redhat.com>
References: <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx> <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx> <20240406150950.GA3060@redhat.com>
 <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com> <20240408184957.GD25058@redhat.com>
 <87il0r7b4k.ffs@tglx> <20240409111051.GB29396@redhat.com>
Date: Tue, 09 Apr 2024 14:02:40 +0200
Message-ID: <877ch67nhb.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=UNuLPP5S;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Tue, Apr 09 2024 at 13:10, Oleg Nesterov wrote:
> On 04/09, Thomas Gleixner wrote:
> It seems that this is because in your tree check_timer_distribution() does
>
> 	if (timer_delete(id)) {
> 		ksft_perror("Can't delete timer");
> 		return 0;
> 	}
>
> while in Linus's tree it returns -1 if timer_delete()
> fails. Nevermind.

Ooops.

>> +static bool check_kernel_version(unsigned int min_major, unsigned int min_minor)
>> +{
>> +	unsigned int major, minor;
>> +	struct utsname info;
>> +
>> +	uname(&info);
>> +	if (sscanf(info.release, "%u.%u.", &major, &minor) != 2)
>> +		ksft_exit_fail();
>> +	return major > min_major || (major == min_major && minor >= min_minor);
>> +}
>
> this looks useful regardless. Perhaps it should be moved into
> tools/testing/selftests/kselftest.h as ksft_ck_kernel_version() ?

Makes sense.

>> +static int check_timer_distribution(void)
>> +{
>> +	const char *errmsg;
>> +
>> +	if (!check_kernel_version(6, 3)) {
>> +		ksft_test_result_skip("check signal distribution (old kernel)\n");
>>  		return 0;
>
> ..
>
>> +	ksft_test_result(!ctd_failed, "check signal distribution\n");
>
> Perhaps
>
> 	if (!ctd_failed)
> 		ksft_test_result_pass("check signal distribution\n");
> 	else if (check_kernel_version(6, 3))
> 		ksft_test_result_fail("check signal distribution\n");
> 	else
> 		ksft_test_result_skip("check signal distribution (old kernel)\n");
>
> makes more sense?
>
> This way it can be used on the older kernels with bcb7ee79029d backported.

Indeed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877ch67nhb.ffs%40tglx.
