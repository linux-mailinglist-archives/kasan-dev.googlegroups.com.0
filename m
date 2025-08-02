Return-Path: <kasan-dev+bncBDXZ5J7IUEIBBS4VXLCAMGQEG6IBCRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id E84B7B19042
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Aug 2025 00:01:49 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-88177d99827sf13970339f.3
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 15:01:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754172108; cv=pass;
        d=google.com; s=arc-20240605;
        b=hE3uoSUEouamCt44Gni4DoI2HhNguZ/C3SbKOqe3T2dmIkfFsF7eqlGrgv4K4NcilW
         UDWSChS5oJDRSXn3FCimu7fO2ZnGV+d1ikVH52z6YGJ7YIRJmhSUn1x4b+Hho6oFv3UZ
         REXgMCxGuRTR+R+h3M6wJfReQo9I8ZgGRso/naJDpUpE2ecg3xGFyyZO6r2NrHH806e8
         lAH2gB9qiHdRnutzACIiYankK8r8ByhxxwKlvQw7gUU9mRGnX2TpMQRF84bmW92kIQeL
         hvVM0LGU+FnqQxp86WKq71uGz6q6EWTl0FMMRuRlm0hJMDbZ09LuwBzfXp+SAy+WXPVh
         dwhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:organization:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=fTb+KmSlRFAqjJcUAYwxCbfjMR4B84JmHQW0VO1FBrY=;
        fh=l+kumhwCXC1xuYor7bi8v1+iVleqAaxVmmG5NhE+S6s=;
        b=bZ30c93D6LEpGJI8MvonVBFlvSh3h+UjRiRv/+oIniSxL/oB4xR2FaGNFDxB65PQG0
         cVxUwo+lf5BESywinzDxqlfusctj64H+q3uFQbGLVCIv2UByeW68P+fmKxe+8yNKhTzc
         ErIGoMiOS+eiTjTxpzHIB9gbPCEu5JTO2hmXDTEhIEehqq2zcMh7kJFBb1Yt7S9Cr3Jt
         FGVBvBy+F+KFIds67/fgXfsg4KFcfQmxomiTNFqTt4pfC1wV+SszLVgDJJzaPPFOKw9c
         ajjZu3s+0bGrXMzGZGC2vqjoczaaVHonS91a975SOVHRxTvjLQ0e6LuMiMREqeV10wfi
         H4Jw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.215.175 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754172108; x=1754776908; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :organization:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=fTb+KmSlRFAqjJcUAYwxCbfjMR4B84JmHQW0VO1FBrY=;
        b=e3EbU68j6mIoMiJD59oWYjFNvu2ilWyneHHo/r4/M4JNa2OQv8aLtOJ11oWhHkq7FG
         HZvT/89fngcq11UoyBmVBSKiyz3TxsLKORAQFPXWnpugp8SOFIlS5PbCE4ROgyRWZvMR
         4hA6/4ufpmDO4A885ZpW8MKt3KnmqLHhqkPsN1oncS28p1Ow5dxx6a89GkNybLLvOxHn
         LPKLl/D4sQi2XGJDHQdREqjME/ihlBQ8m7BBi4biVeX9TpcgdpHsxZdP06Vg+6uR2Y1y
         MVRd2n27v2UnWf36XrW+1lrn4en80jXrEzqxlTAmFrWAVbice6+MHRuAqwJgGO/AiTEF
         3dBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754172108; x=1754776908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fTb+KmSlRFAqjJcUAYwxCbfjMR4B84JmHQW0VO1FBrY=;
        b=iyx9Rj10CzzS0jW88RcomDPpSdT9ov0zJeJ0XQ2IPYhjJNQb1kGHqgjsPnh/tRl0SV
         nsGE6gTET1F7/iG1kpmc3k3MogFZhsDbGZ9cimT6BnKtOSn9O0wIXayXo492WXO+/GFW
         2IDCZDIeIpqktyMvM7eTX+4kYSujHdFt94GnlPdpSEQ0sVVDw+BNrIjyJrC5fbkw40n7
         ThY/fpbX5c5R86jUFhxxqz4aKa8E07xuUIrgS/yOiaUKCXhoX7H+WPssiwjN/WdYHwbK
         q0ZBlWJYpckrYAsBz23mZ1z9YVoCEDa29Nje/qQ/U91P7YYnCZmGNHX+h/ZUdhvFrABf
         1+uw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdglgw69Q17+VEpAocY7lqV+ZlbOz8kKACKApb85EZa+Uo3etDh4Pa/GogtsVmjFeVP5WFDA==@lfdr.de
X-Gm-Message-State: AOJu0YwTDnneMAGnqOxEk2zHqbzVrl71A0G8d/BOP3QEPD5vH1HJbbjZ
	ogf2LRARFfSWqS27NBhsY3/vqknfWBiIKA7Y9QvFzDksnSpCf12L6F/7
X-Google-Smtp-Source: AGHT+IHIrKvKMil6dJCda3Pfeuj//Y0596+njnEP7erbcfOaxgOTVahUPS4ktStKNDeyEVEwsAGUjQ==
X-Received: by 2002:a05:6e02:23c6:b0:3e2:9838:31ac with SMTP id e9e14a558f8ab-3e416376239mr94355175ab.18.1754172108136;
        Sat, 02 Aug 2025 15:01:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfinUI4FSRPaI+pV8trqHRVAN2RX4e7DJw0tONt3diTmg==
Received: by 2002:a92:cd8b:0:b0:3dd:b672:7f90 with SMTP id e9e14a558f8ab-3e401b89694ls28075935ab.1.-pod-prod-06-us;
 Sat, 02 Aug 2025 15:01:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/Px5Sh0rIsoz75C6qW/McM31eHjcuozrVaaebomas+ffv4PqmBVK9okL2P7RMVzid8MlJB9/KwZ8=@googlegroups.com
X-Received: by 2002:a05:6e02:370d:b0:3e2:8e44:8240 with SMTP id e9e14a558f8ab-3e416345ab5mr81201785ab.11.1754172107164;
        Sat, 02 Aug 2025 15:01:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754172107; cv=none;
        d=google.com; s=arc-20240605;
        b=fsMoqtAH0kwzO1kQXL8KbQQoBTN11PpdC0afzmJK4Tdf07d7tXhwVemqvrNApRFuau
         q+HJ+E9eEMuTZPXA58W/lLyUpjiqwFLMzTSKI5fFYRqGE2P1nB3AxzGPBF+06aZtJjQI
         CRumyO3BQenabJp7p7lgHfNSrZnezqZgMnhvq6Mcnc5GRQpmZQ37ajAtYY9Jo4ck6q6D
         f8Eou5W0KMU7j7T/30WCDI4DqLmAx6UNxwJCOUSDdc/RPLTL/6yzSlwhtX779kUaUnJL
         CM1Y4F5eYtmkSL7NvQSx4byTE3bXLMMVZB+SpH+DKW1TivxtaFRFnslTdqdiBj/BNZbe
         1P6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:organization:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id;
        bh=n6iKlbJNv1rMzXvKJJrDKnOLYsLImNj0w08vdZLLiFg=;
        fh=/xEiuGZ64e+AqjyCAgSXvYYSN5O02VYyzxybaBdk+po=;
        b=lkIaUVm0nUUyZvapPOyXRsLWg8gnObyQDwXyn0QXCPQaWtHH+k16lWo1UMbj6AD04G
         ED1jYA2oVja6pttK9Zeu0zMBRb3RSanW84VGCus1Sruq5Ctf+X0X6CCPXeFeC7hfkt5q
         qPlwCoetEo5lH32SOhdv7yTX3uNw07+1gOMo8TFYh8OY/Z1zJvrg4HyTptDnlCkPsmRa
         oyXNT/oacEokVfNuffaU6MF0ArRTB9Ew5a93gfqAkSubpzkrjtxQp7t9Ih4aeSoK4Jyj
         Qr0CYv4ovyBmA2P4MXX2NiexFNopDUcj9ez+hvK+L3ByhD2ZaU+k916s72PjU52jmpyX
         d4eg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.215.175 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pg1-f175.google.com (mail-pg1-f175.google.com. [209.85.215.175])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e402b1e315si2895955ab.4.2025.08.02.15.01.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 15:01:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.215.175 as permitted sender) client-ip=209.85.215.175;
Received: by mail-pg1-f175.google.com with SMTP id 41be03b00d2f7-b3f4ae9a367so424863a12.3;
        Sat, 02 Aug 2025 15:01:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUIakzyxvEM0RkaNH5u2YOMRA8a2Z2B0xxEPVyYAyR/GxEFkV744mDacBhvkS/NZKavrmCwOfCCTWo=@googlegroups.com, AJvYcCWvo+3rBc9fnRgWTtZIQOBqL9r5DBy/qlzQpXx3taLWSIBS7+RBhhK5FG8OkvODFAQ6yqe+kite+G2O@googlegroups.com
X-Gm-Gg: ASbGncvFtSH8EBIYgBfLQvVpdxghz4oSp3tNlEk0GhW5hf/tvfkXx1fkyopJnueD3HK
	nd+lr7nL1/TSItqv31A75Fn9UZa3yQIgy3ptDHLtdR6qs9A6tmHnDJIjJWfNSeyNNtLgXmIzL5O
	hchnnRe+RO34uRvpA/VhrPfKrBfLTqtgGJs110t5umxRLwbHDbqpctJi6ShxB3j5RQZQseq88L5
	RxZA4p+aDxsqq/6/kwd68JnXeIrIM3/rXSDjanlILjIqfZfx+SbqgCDg5hLEy0GZtWSmF6zFGAm
	/ghSepr15u1XY+NMj76cGfoE49OaIMEXsxy9Xy2yZQmU+gyjCl1qoTwJGMALdbPxcik4Fy88SFx
	r+4A1wKfwH/NjbKMDW78QnLMoyOsGV39z
X-Received: by 2002:a05:6a00:4b52:b0:736:4d90:f9c0 with SMTP id d2e1a72fcca58-76bec2f5dd1mr2171800b3a.1.1754172106326;
        Sat, 02 Aug 2025 15:01:46 -0700 (PDT)
Received: from [192.168.50.136] ([118.32.98.101])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-76bccfbcfb6sm7056787b3a.79.2025.08.02.15.01.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 15:01:45 -0700 (PDT)
Message-ID: <4a505533-b725-4e3f-94db-3d261937ea25@kzalloc.com>
Date: Sun, 3 Aug 2025 07:01:40 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kcov, usb: Fix invalid context sleep in softirq path
 on PREEMPT_RT
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Byungchul Park <byungchul@sk.com>,
 max.byungchul.park@gmail.com, "ppbuk5246 @ gmail . com"
 <ppbuk5246@gmail.com>, linux-kernel@vger.kernel.org,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Alan Stern <stern@rowland.harvard.edu>, Thomas Gleixner
 <tglx@linutronix.de>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 stable@vger.kernel.org, kasan-dev@googlegroups.com,
 syzkaller@googlegroups.com, linux-usb@vger.kernel.org,
 linux-rt-devel@lists.linux.dev
References: <20250802142647.139186-3-ysk@kzalloc.com>
 <2025080212-expediter-sinless-4d9c@gregkh>
Content-Language: en-US
From: Yunseong Kim <ysk@kzalloc.com>
Organization: kzalloc
In-Reply-To: <2025080212-expediter-sinless-4d9c@gregkh>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.215.175 as
 permitted sender) smtp.mailfrom=yskelg@gmail.com
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

Hi Greg,

On 8/3/25 6:30 =EC=98=A4=EC=A0=84, Greg Kroah-Hartman wrote:
> On Sat, Aug 02, 2025 at 02:26:49PM +0000, Yunseong Kim wrote:
>> The KCOV subsystem currently utilizes standard spinlock_t and local_lock=
_t
>> for synchronization. In PREEMPT_RT configurations, these locks can be
>> implemented via rtmutexes and may therefore sleep. This behavior is
>> problematic as kcov locks are sometimes used in atomic contexts or prote=
ct
>> data accessed during critical instrumentation paths where sleeping is no=
t
>> permissible.
>>
>> Address these issues to make kcov PREEMPT_RT friendly:
>>
>> 1. Convert kcov->lock and kcov_remote_lock from spinlock_t to
>>    raw_spinlock_t. This ensures they remain true, non-sleeping
>>    spinlocks even on PREEMPT_RT kernels.
>>
>> 2. Refactor the KCOV_REMOTE_ENABLE path to move memory allocations
>>    out of the critical section. All necessary struct kcov_remote
>>    structures are now pre-allocated individually in kcov_ioctl()
>>    using GFP_KERNEL (allowing sleep) before acquiring the raw
>>    spinlocks.
>>
>> 3. Modify the ioctl handling logic to utilize these pre-allocated
>>    structures within the critical section. kcov_remote_add() is
>>    modified to accept a pre-allocated structure instead of allocating
>>    one internally.
>>
>> 4. Remove the local_lock_t protection for kcov_percpu_data in
>>    kcov_remote_start/stop(). Since local_lock_t can also sleep under
>>    RT, and the required protection is against local interrupts when
>>    accessing per-CPU data, it is replaced with explicit
>>    local_irq_save/restore().
>=20
> why isn't this 4 different patches?

Thank you for your feedback on the patch. I=E2=80=99ll split it into four s=
eparate
patches for v3 to improve clarity.

Best regards,
Yunseong Kim

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
a505533-b725-4e3f-94db-3d261937ea25%40kzalloc.com.
