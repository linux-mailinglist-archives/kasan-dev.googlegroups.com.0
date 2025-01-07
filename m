Return-Path: <kasan-dev+bncBCMIZB7QWENRBTF76O5QMGQEL2J2ONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BBA9A03932
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jan 2025 09:03:26 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-3862e986d17sf6642967f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2025 00:03:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736237006; cv=pass;
        d=google.com; s=arc-20240605;
        b=KMYtwhuOLimYNIjvY/o3eFyN/Qmxn12Y+YL5/a2DY1oOf0Aq+lnqJWxOhtbIxTrfm1
         i0mNYBAC10dvfowBxA59V+D+SV7BeULe3Ri+LGcnPWxKugEwNXygpEP9eGu2s/QmXKz3
         RZbv0TtGGvjl9EoPnRLIBaO9/LGMFwEWEHWUA60hfd9CPyJSEARWhrycnhTPPK/+8sB3
         kZA8T4x8xDSNKCcX0F1fVJ9gWX2/KBerUAtwcp8lbcS5u1S8YWBCOgSRNBqAMmt5up6V
         OxegE0OdxXdArJCUARG3xYLoW9AKTUDdBsQ5ByE+J9yTnzu2LusOK5/u2ZjiNL84jWjc
         w5rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kOqucU8Y6uzFlRIz2hQM0HGQZQRnh3tYy/7CnAtjFyY=;
        fh=Gb6rGagUdzfsBTEzOjCSKa5HwR2CNPYJhHL19o7D7z8=;
        b=EK1m/VyhLiQH8Af6Qj3m/jH1O+IC3tTlwyJRgO4dn4ZMj9YIiSYcM7n5oxbnuAGjAT
         d7cRFe0Sac/mhPKGPPak8+Q1Mx3I+l0RNF8oKCCO691kj82P9P5z0dAKp2oxkGK7NOiK
         2efVUtcK9//clJDl6Alq+rOnQ9B4lTJ0WxahkTrUyCwfqVaK3qDnt4w/eSyEAWpDmNLg
         d2hIjGrrS4HFpLCPbXb5MzAyIArlQDzSnwCWSVWdITkGQuDnzlWi+z3fJA1Zx14hi3px
         IrSBXALOd/C4JfLzQXR9vAOWCA4KXl0Ask9/fzxEsmlZd4dnGv90XZZB13fUx4habB9G
         0x2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WBWLho41;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736237006; x=1736841806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kOqucU8Y6uzFlRIz2hQM0HGQZQRnh3tYy/7CnAtjFyY=;
        b=nVl+QvQIYGZzBpqsrh5RujZUzX/l5Eeond6W9FwdFWNdICt8DPc03ioBmAk7GaS9q5
         yQLoKj+YGsOFKlrkX2OETPiqnt1/3ZnqpOyxD3cqlanfZui8SFGivMOcjeS7pxYUY81p
         Pzt3uEwYN8S3EiDTC5YVsczBF3jlzv1tYMRc9hiVngnEdo+/XHOl8zPX9SPYEnNQTFQ2
         TJyt/XTyGsgC4AEl3p/odPDU/+Ik57ckySbJzYBIl1W8HbvBoVgGf9CUM/Omkn+Pmk/8
         m/f4XhMqe5sLGltNEGQtNXXCcH5bVywXvyvAWkhYWFgsJcN/0bx97TSfz1REcyMEEG0g
         6hiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736237006; x=1736841806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kOqucU8Y6uzFlRIz2hQM0HGQZQRnh3tYy/7CnAtjFyY=;
        b=OvZvdvfUrFFLZknv7kETHJ7ATT2zrEBUIfDn7wOQAyqYFfdezpgwXwMO9ZSadnFPDG
         Lm1Q5V+ee/qODDWT7RL+Z4w+djepshEbxO3RIpkdfe/kwXrDpAw4b682WUPdTJ+r7oYy
         kNrgjNlCVLvtNHRLdbfW5TENe4AwwC7okCx5v80aL4K19UHMoR4g7FTQw6o+wR4BGtXT
         Xr3BHC7/Ut0y86JrHA6fVTlkpX70H9Pj44BtSDbchvNiN7aUpxUmp02/pgxgDbnz1hi8
         pUzB57CXVbTgIgFFdQshi5p1KDMSFF75x1K3ir9ahnLGQogRSz8NxwQMZB88Sj6Kglqa
         ASzg==
X-Forwarded-Encrypted: i=2; AJvYcCVFeD3gv08YtP7ATU4tPlpYEOSuIMWDMU024Ri0V0czo1eolajafLzngKwWJgKstZkp3HT3rA==@lfdr.de
X-Gm-Message-State: AOJu0YxbVOEkXXaQ+wNO/eSwgfX6D+oAmbCL2Dqlv3RjO+PcF0yNywW2
	7J8S2HCnuvO38ZrNYdogjjFH1AMT5RyvrlaZ0R9DOH++AplQHSz3
X-Google-Smtp-Source: AGHT+IH7JLX78PzeuHjTEslqZi/SqboZJtfUSvcO2AmHOGVuqWmSia7W6Td53yTO3sbddAm20T4zvQ==
X-Received: by 2002:a05:6000:4802:b0:386:3684:c97e with SMTP id ffacd0b85a97d-38a221f170bmr40566432f8f.23.1736237005325;
        Tue, 07 Jan 2025 00:03:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5107:b0:434:f37c:2a56 with SMTP id
 5b1f17b1804b1-4365c517773ls22547475e9.1.-pod-prod-03-eu; Tue, 07 Jan 2025
 00:03:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUjJvqS6zWlwtDAMQL6zrVEUiTKD2E7XLrFiqUyvLsSoxCCbakbhbcyinKpGq304u00i8cHeMnK/Co=@googlegroups.com
X-Received: by 2002:a05:600c:314a:b0:434:f7e3:bfbd with SMTP id 5b1f17b1804b1-43668b49929mr465301405e9.23.1736237003276;
        Tue, 07 Jan 2025 00:03:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736237003; cv=none;
        d=google.com; s=arc-20240605;
        b=SDBcAGGbuZ2/b6NCuaweUdA0bWSKI5m9qVVeJ2PrWMPXSDn7wghcXTcF4/i0e3tUwH
         FvoJSdFhoE7SKyJFieAIcQ9ZnrDrFvPK8a/CJcXrIAm3rsoFMVX6CwM4mt/sUXB8isSA
         e73EdZpbnG1jHfcjxccLrPVh/RlLyMVR7K85jm63bHWyvd9wmiioqbWWKCukA125HklQ
         wM2CmamMXo3BsWzBktdZtoqNZNjpF8sb+QMy4l5YYwONTcrn8TNiA+Nj5qghbKKpUIfU
         LWtJNu07fmaiFIdYhJSSvBulQLLLA6nfIpBlfcPlxTB2XVpUWatI6ab47aVLsDkJJagJ
         /Tjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=a06nUKnwqRyYX+5sz0Woija8YPIS9M+5EMh+rcIETuM=;
        fh=hUl1UtFwAZhA0YNqSGPoIJYvHzZZw8e9Mw6WFjwW81M=;
        b=SsaPhuwfTfY3YALTzdSUugBGfRZOfjHmdEDbrZWgWgPyQ8hoQSnQPjmck9LJxqLw95
         YB2kUdiYteIybzalk5PAWcUDS1+391SXtTB0eAe2Jqc62sQ1UDR7HC20yd2ORpdC5POZ
         evFGBcR7DVHJeYsCUGAASXRDYLzg/xGdXdWBkosSWhdNJjpHSGGwDcW0u0LWwrcOf/Gg
         RGukpSzmx5g6PH3uvJWV7+1yhjtixnC48pMxksiSoDs8mlEI8VAKLra+SUI4a++ktQET
         Dn9I2qd1nh2ai7JudWr+ZMit562Cp8gpkRU2Hk2W+jT1WTO8UTVdZvpLg73FIpFDYgSz
         vYzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WBWLho41;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4366112e034si7010805e9.0.2025.01.07.00.03.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Jan 2025 00:03:23 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id 38308e7fff4ca-3003e203acaso153446981fa.1
        for <kasan-dev@googlegroups.com>; Tue, 07 Jan 2025 00:03:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX14ZsTyFXPSyBqalOTZw28/uD3Lx8dxYsfr60Veok0UJ2zzzW+9FQI+uASSaXyLnnzXOnvLoenhAk=@googlegroups.com
X-Gm-Gg: ASbGnctMlgIar/pVJMXfcRmqnB3hgyu9jYv5BR5z9QYXaYtMnIPDmkXJtl0mPknXYz9
	YzfdRIVzNlwHEpKKOp4lAWTlLKYhRQgerYrtKOElNKX/Sn1G0GlMv2Ag+P9bZ/DqY3dvyX6M=
X-Received: by 2002:a05:651c:154b:b0:302:2320:dc81 with SMTP id
 38308e7fff4ca-304685c281dmr237952001fa.29.1736237002148; Tue, 07 Jan 2025
 00:03:22 -0800 (PST)
MIME-Version: 1.0
References: <F989E9DA-B018-4B0A-AD8A-A47DCCD288B2@m.fudan.edu.cn>
In-Reply-To: <F989E9DA-B018-4B0A-AD8A-A47DCCD288B2@m.fudan.edu.cn>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Jan 2025 09:03:10 +0100
X-Gm-Features: AbW1kvZWP5gFV_d5gNb_YsXXEl_eAx0UouHxgqPbHD5lJG4CSJWTEgVTjeVhxNU
Message-ID: <CACT4Y+YkkgBM=VcAXe2bc0ijQrPZ4xyFOuSTELYGw1f1VHLc3w@mail.gmail.com>
Subject: Re: Bug: Potential KCOV Race Condition in __sanitizer_cov_trace_pc
 Leading to Crash at kcov.c:217
To: Kun Hu <huk23@m.fudan.edu.cn>
Cc: andreyknvl@gmail.com, akpm@linux-foundation.org, elver@google.com, 
	arnd@arndb.de, nogikh@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WBWLho41;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 2 Jan 2025 at 04:21, Kun Hu <huk23@m.fudan.edu.cn> wrote:
>
> Hello,
>
> When using our customed fuzzer tool to fuzz the latest Linux kernel, the =
following crash
> was triggered.
>
> HEAD commit: dbfac60febfa806abb2d384cb6441e77335d2799
> git tree: upstream
> Console output: https://drive.google.com/file/d/1rmVTkBzuTt0xMUS-KPzm9Oaf=
MLZVOAHU/view?usp=3Dsharing
> Kernel config: https://drive.google.com/file/d/1m1mk_YusR-tyusNHFuRbzdj8K=
UzhkeHC/view?usp=3Dsharing
> C reproducer: /
> Syzlang reproducer: /
>
> The crash in __sanitizer_cov_trace_pc at kernel/kcov.c:217 seems to be re=
lated to the handling of KCOV instrumentation when running in a preemption =
or IRQ-sensitive context. Specifically, the code might allow potential recu=
rsive invocations of __sanitizer_cov_trace_pc during early interrupt handli=
ng, which could lead to data races or inconsistent updates to the coverage =
area (kcov_area). It remains unclear whether this is a KCOV-specific issue =
or a rare edge case exposed by fuzzing.

Hi Kun,

How have you inferred this from the kernel oops?
I only see a stall that may have just happened to be caught inside of
__sanitizer_cov_trace_pc function since it's executed often in an
instrumented kernel.

Note: on syzbot we don't report stalls on instances that have
perf_event_open enabled, since perf have known bugs that lead to stall
all over the kernel.

> Could you please help check if this needs to be addressed?
>
> If you fix this issue, please add the following tag to the commit:
> Reported-by: Kun Hu <huk23@m.fudan.edu.cn>, Jiaji Qin <jjtan24@m.fudan.ed=
u.cn>
>
> --------------------------------
> rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> rcu:    0-....: (36 ticks this GP) idle=3D5a54/1/0x4000000000000000 softi=
rq=3D28602/28602 fqs=3D20758
> rcu:    (detected by 2, t=3D105010 jiffies, g=3D53165, q=3D148274 ncpus=
=3D4)
> Sending NMI from CPU 2 to CPUs 0:
> NMI backtrace for cpu 0
> CPU: 0 UID: 0 PID: 2946 Comm: syz.1.149 Tainted: G    B              6.13=
.0-rc4 #1
> Tainted: [B]=3DBAD_PAGE
> Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubunt=
u1.1 04/01/2014
> RIP: 0010:__sanitizer_cov_trace_pc+0x22/0x60 kernel/kcov.c:217
> Code: 90 90 90 90 90 90 90 90 f3 0f 1e fa 55 bf 02 00 00 00 53 48 8b 6c 2=
4 10 65 48 8b 1d 78 11 7a 6b 48 89 de e8 40 ff ff ff 84 c0 <74> 27 48 8b 93=
 e0 14 00 00 8b 8b dc 14 00 00 48 8b 02 48 83 c0 01
> RSP: 0018:ffa0000000007698 EFLAGS: 00000046
> RAX: 0000000000000000 RBX: ff110000386f0000 RCX: ffffffff949eb81e
> RDX: 0000000000000000 RSI: ff110000386f0000 RDI: 0000000000000002
> RBP: ffffffff949eb8c3 R08: 0000000000000000 R09: fffffbfff4177aab
> R10: fffffbfff4177aaa R11: ffffffffa0bbd557 R12: ff11000002b9ab50
> R13: 0000000000000000 R14: 1ff4000000000edc R15: ff11000053a361a8
> FS:  00007f403e2c1700(0000) GS:ff11000053a00000(0000) knlGS:0000000000000=
000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: 0000000000000001 CR3: 0000000024264004 CR4: 0000000000771ef0
> PKRU: 80000000
> Call Trace:
>  <NMI>
>  </NMI>
>  <IRQ>
>  perf_prepare_sample+0x803/0x2580 kernel/events/core.c:7977
>  __perf_event_output kernel/events/core.c:8079 [inline]
>  perf_event_output_forward+0xd3/0x2c0 kernel/events/core.c:8100
>  __perf_event_overflow+0x1e4/0x8f0 kernel/events/core.c:9926
>  perf_swevent_overflow+0xac/0x150 kernel/events/core.c:10001
>  perf_swevent_event+0x1e9/0x2e0 kernel/events/core.c:10034
>  perf_tp_event+0x227/0xfe0 kernel/events/core.c:10535
>  perf_trace_run_bpf_submit+0xef/0x180 kernel/events/core.c:10471
>  do_perf_trace_preemptirq_template include/trace/events/preemptirq.h:14 [=
inline]
>  perf_trace_preemptirq_template+0x287/0x450 include/trace/events/preempti=
rq.h:14
>  trace_irq_enable include/trace/events/preemptirq.h:40 [inline]
>  trace_hardirqs_on+0xf2/0x160 kernel/trace/trace_preemptirq.c:73
>  irqentry_exit+0x3b/0x90 kernel/entry/common.c:357
>  asm_sysvec_irq_work+0x1a/0x20 arch/x86/include/asm/idtentry.h:738
> RIP: 0010:get_current arch/x86/include/asm/current.h:49 [inline]
> RIP: 0010:__rcu_read_unlock+0xc6/0x570 kernel/rcu/tree_plugin.h:440
> Code: b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 0f b6 04 02 84 c0 7=
4 08 3c 03 0f 8e bf 01 00 00 8b 85 00 04 00 00 85 c0 75 57 <65> 48 8b 1d 02=
 af 92 6b 48 8d bb fc 03 00 00 48 b8 00 00 00 00 00
> RSP: 0018:ffa0000000007e08 EFLAGS: 00000206
> RAX: 0000000000000046 RBX: ff11000053a3d240 RCX: 1ffffffff4177c76
> RDX: 0000000000000000 RSI: 0000000000000101 RDI: ffffffff947103e2
> RBP: ffffffff9ed26380 R08: 0000000000000000 R09: 0000000000000000
> R10: fffffbfff4177aaa R11: ffffffffa0bbd557 R12: 0000000000000001
> R13: 0000000000000200 R14: ffa0000000007e00 R15: 1ff4000000000fc9
>  rcu_read_unlock include/linux/rcupdate.h:882 [inline]
>  ieee80211_rx_napi+0x117/0x410 net/mac80211/rx.c:5493
>  ieee80211_rx include/net/mac80211.h:5166 [inline]
>  ieee80211_handle_queued_frames+0xd9/0x130 net/mac80211/main.c:441
>  tasklet_action_common+0x279/0x810 kernel/softirq.c:811
>  handle_softirqs+0x1ad/0x870 kernel/softirq.c:561
>  __do_softirq kernel/softirq.c:595 [inline]
>  invoke_softirq kernel/softirq.c:435 [inline]
>  __irq_exit_rcu kernel/softirq.c:662 [inline]
>  irq_exit_rcu+0xee/0x140 kernel/softirq.c:678
>  instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inli=
ne]
>  sysvec_apic_timer_interrupt+0x94/0xb0 arch/x86/kernel/apic/apic.c:1049
>  </IRQ>
>  <TASK>
>  asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.=
h:702
> RIP: 0010:__sanitizer_cov_trace_pc+0x0/0x60 kernel/kcov.c:210
> Code: 48 8b 05 b3 11 7a 6b 48 8b 80 f0 14 00 00 e9 32 a1 e6 07 0f 1f 80 0=
0 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 <f3> 0f 1e fa 55=
 bf 02 00 00 00 53 48 8b 6c 24 10 65 48 8b 1d 78 11
> RSP: 0018:ffa0000007f17db0 EFLAGS: 00000246
> RAX: 0000000000000000 RBX: 0000000000000200 RCX: ffffffff947854c4
> RDX: 0000000000000200 RSI: ff110000386f0000 RDI: 0000000000000002
> RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
> R10: fffffbfff4177aaa R11: ffffffffa0bbd557 R12: ffa0000007f17ec0
> R13: dffffc0000000000 R14: dffffc0000000000 R15: 1ff4000000fe2fd8
>  __seqprop_raw_spinlock_sequence include/linux/seqlock.h:226 [inline]
>  ktime_get_ts64+0xe4/0x3c0 kernel/time/timekeeping.c:952
>  posix_get_monotonic_timespec+0x78/0x260 kernel/time/posix-timers.c:156
>  __do_sys_clock_gettime kernel/time/posix-timers.c:1148 [inline]
>  __se_sys_clock_gettime kernel/time/posix-timers.c:1138 [inline]
>  __x64_sys_clock_gettime+0x15c/0x260 kernel/time/posix-timers.c:1138
>  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
>  do_syscall_64+0xc3/0x1d0 arch/x86/entry/common.c:83
>  entry_SYSCALL_64_after_hwframe+0x77/0x7f
> RIP: 0033:0x7f403f808ba5
> Code: c0 4c 89 63 08 48 8d 65 d8 5b 41 5c 41 5d 41 5e 41 5f 5d c3 83 f8 0=
2 0f 84 e6 02 00 00 44 89 e7 48 89 de b8 e4 00 00 00 0f 05 <48> 8d 65 d8 5b=
 41 5c 41 5d 41 5e 41 5f 5d c3 81 7e 04 ff ff ff 7f
> RSP: 002b:00007f403e2c0b20 EFLAGS: 00000293 ORIG_RAX: 00000000000000e4
> RAX: ffffffffffffffda RBX: 00007f403e2c0ba0 RCX: 00007f403f808ba5
> RDX: 0000000000000002 RSI: 00007f403e2c0ba0 RDI: 0000000000000001
> RBP: 00007f403e2c0b70 R08: 00007f403f804010 R09: 0000000000032b26
> R10: 7fffffffffffffff R11: 0000000000000293 R12: 00007f403e2c0ba0
> R13: 00007f403f82ff8c R14: 00007f403f830018 R15: 00007f403e2c0d40
>  </TASK>
>
>
> ---------------
> thanks,
> Kun Hu

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACT4Y%2BYkkgBM%3DVcAXe2bc0ijQrPZ4xyFOuSTELYGw1f1VHLc3w%40mail.gmail.com.
