Return-Path: <kasan-dev+bncBCCMH5WKTMGRBX7FSWWAMGQEYX7QGQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 65C3F81C916
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Dec 2023 12:28:33 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6da6608ac3csf2085524a34.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Dec 2023 03:28:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703244512; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYPyIgXGcdUR6y9hacrOiXx/8+w73mWEKh41dfwQXq6dW23MdPsjYFnonttybpSp8e
         XNTbuqvfKSlj5kzuZ3N+AukjLKDgMpp1yvTGMgQMFbOPuERL2Bn3vDnD7NcZJ3DDJUq1
         VeZ8Z5qfiS4kqO8VJ51tKnWTRsHuz9iwWblEK3qIOS5sriL1EPf2vF5DXF4NLACsOE4K
         bZ5KxsBtRaOt/Ox2pix1gdOvpSrNkGp+RqWZG509xXb25LQkQcN1qOFwAdDVdcF1enqn
         55qk6zoMN8Xvm4IwbcdxsgTHTRYXVBFZLS/6jLdxlmthoN1gBYrcObROc8fljEzeXN4l
         4dXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A/uyQZH2uU1sBQFIHdGeacK0hTFdKZyOMn7btY2Zn3Y=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=TxcjYF/DPG1xEVURbT2rrDp/dIFiRbZuhDAIgFGoPPuXKoucVjNuLgvJ1ZJJoA4CxA
         swG89K74F6CFF+ofNBLSWOw/iyTgJnieQaStiy8yLVFZwN3O18O9TJNscNFeSo9a82zx
         69pkKKdIO2Uf3zGK3KrzVlgjjtyKEF4fZZ7UVLaOD/0RVjP9FzEG+SGs9fEMZDbDXlI5
         BMohBy+OZ2XYe8S1pneJdddGxexW16Qx6FZN8i99r8zzYTHVDQY84ZbSjLIqVhL+Uq1m
         N6M0T5mmZbZZJzXDn0J/RppkiIpqa1WdGNjbYFGx8QeefNNEIk7bKxfBdgaWLNquaHgd
         ishw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RmyJUROd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703244512; x=1703849312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A/uyQZH2uU1sBQFIHdGeacK0hTFdKZyOMn7btY2Zn3Y=;
        b=N7Bjkmhw4BTWp8/o0Hk3HXE5nh1+aOcGckymOsiorngX8hxDEJaO3SPUg6jEiT7T4b
         RBVthizAiDJOQ/Y0ZQ515pcBYdw4ZJi93wyTLQo8/x6yqUHzN42AsahdXG8FRKeGwrE3
         KZZkprdsIHhB+grp3W0+Cl8sEdEoNfGLBjK9l7Xem0kWOmBtgHBW7U2/pC+mm7fhwe5n
         8Sqs2oCE3Ov+AAkqhpMVOZAcNCr6X/k9K8hid3jVYo5FDxqKXm8z0EIfE6/4mtdwJkqS
         g2xoK+NijWjJdDSsZ7GCFdRlEfXdvJQgC0z76bVOH30tkcxgbIUJAZm4QuF6w+QtnOqo
         Hnrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703244512; x=1703849312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A/uyQZH2uU1sBQFIHdGeacK0hTFdKZyOMn7btY2Zn3Y=;
        b=eiMMB59EsBarz3e6vx61K3UgdBCMLSRbXlatgaiaGYmpYtCMAP1D7vyO7mrubzO7gh
         rDoma8j/DFL6i0WkFIV0JY2/Dl1nj5X4yyyg/lTUCGWvE11+d73TA+fLr3NAv6axSe5p
         D3LH2AigdPawypn2f8qKtLyRR2lSz0mbMZJr4Bqs3TqL74lcwDdB5ZWl4JPiwSyNWxYb
         nhnP012r0nD9CGD2VM1rLX+P7/1iUSsA5G1RR7S2DN/bIg5IzBpMslYgHjsZgpkwoN9L
         sw7Uz4jm5leAbGS7kk1Xpi9KP28F6jdqwCiYupBt0CdtPjMyGl4m41IvoohrhePhZR0u
         XKOw==
X-Gm-Message-State: AOJu0YzweK7ZBY0/YT6EH1wUXnZndUvwDuy6GHK43MAxCU1BA4xSKGuw
	B+8xfEpnIS9XLf3RaMtkN54=
X-Google-Smtp-Source: AGHT+IHbxW2LFrYvnG5PU/fNbPHBPi4Um1JNGgsnUgqeSilLGBR9zSD+gjUqRif2OrJ4H/lWqo9ULg==
X-Received: by 2002:a05:6870:3310:b0:204:1583:c42a with SMTP id x16-20020a056870331000b002041583c42amr1586413oae.65.1703244511619;
        Fri, 22 Dec 2023 03:28:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:521e:b0:1fb:6f8:e871 with SMTP id
 ht30-20020a056871521e00b001fb06f8e871ls2597075oac.0.-pod-prod-09-us; Fri, 22
 Dec 2023 03:28:31 -0800 (PST)
X-Received: by 2002:a05:6808:1898:b0:3ba:2af:c7da with SMTP id bi24-20020a056808189800b003ba02afc7damr1583678oib.110.1703244510830;
        Fri, 22 Dec 2023 03:28:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703244510; cv=none;
        d=google.com; s=arc-20160816;
        b=Z3t4Dc+hCDxn9x0HV21oLdw9GoN5dAYlQwQbmcp7wcPwRW3qMiQXLzLBx6n19W1030
         zY3M6hOs+7cgUCl5sgdLxw8spfDPIsiHHStWO3N++ijFI4uBdiF4BWn3YIA0GrJPmUvd
         xWbEogpoz+YwWQ/0AC8R58Cb28hNlVVB9Pw00DaozIaPXGqBYID9vxnuX+SttFiW2obF
         MHWXKAfEPwMm6ZHJu1RDtD49UFvCfKrIddXJpXmX0oG/eX7NBLLflag8EHfYGLTo9XO9
         KhWreTpiBUUcuEBH5+w0BG6vKHgInpGjNROxWJ0n0jwF1jqABsGkBR7yx6zQpqYQv3zr
         GZyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1p7KqUeaWemOFaHH+JSolT+/fQ/fl1zP2/9KT4NrzQs=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=YLfkw075wV9SY/6kY5ExT0btJPaU+HSYlMTUW2P7D5PIIeWTyz7IOE+EvnWQRmBTzA
         J0zWKdgIaP+4uAxXddvcPDlSA4IH6iDEcg35ikWxvFhcwl+4Nw9hRCUOgyDM2+n2+ktY
         /7b+TKeUiT8672DxF5vcp0eC8aYNPj7hm1Vrotz9hMWgmaGxC8YAtNhbU+Ok+rSg9qrJ
         5uh7tMJJRG4OgBDNWh0c9KH37fz5dYD9uVaWARU8lceSyY+POUlmzKH30h3GQ9gvgrfw
         a1719/SlrP7S6N1bQDDPR5M5GeSpGCTP4hHTrc03yFlVFZuuqn0OjWZOzIyN+/TVRWJy
         Q3KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RmyJUROd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id bd8-20020a056808220800b003bb7afbe66csi275443oib.4.2023.12.22.03.28.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Dec 2023 03:28:30 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id d75a77b69052e-427aa3ed4d7so4214621cf.1
        for <kasan-dev@googlegroups.com>; Fri, 22 Dec 2023 03:28:30 -0800 (PST)
X-Received: by 2002:a05:6214:62a:b0:67f:9eb:f1ec with SMTP id
 a10-20020a056214062a00b0067f09ebf1ecmr1541233qvx.56.1703244510192; Fri, 22
 Dec 2023 03:28:30 -0800 (PST)
MIME-Version: 1.0
References: <20231213233605.661251-1-iii@linux.ibm.com> <20231213233605.661251-28-iii@linux.ibm.com>
In-Reply-To: <20231213233605.661251-28-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Dec 2023 12:27:50 +0100
Message-ID: <CAG_fn=VfYNpMynQtXiKemoDy3LjH5Hn8N-VpzH6AGVZ3jDHPUQ@mail.gmail.com>
Subject: Re: [PATCH v3 27/34] s390/irqflags: Do not instrument
 arch_local_irq_*() with KMSAN
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RmyJUROd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Dec 14, 2023 at 12:36=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> KMSAN generates the following false positives on s390x:
>
> [    6.063666] DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
> [         ...]
> [    6.577050] Call Trace:
> [    6.619637]  [<000000000690d2de>] check_flags+0x1fe/0x210
> [    6.665411] ([<000000000690d2da>] check_flags+0x1fa/0x210)
> [    6.707478]  [<00000000006cec1a>] lock_acquire+0x2ca/0xce0
> [    6.749959]  [<00000000069820ea>] _raw_spin_lock_irqsave+0xea/0x190
> [    6.794912]  [<00000000041fc988>] __stack_depot_save+0x218/0x5b0
> [    6.838420]  [<000000000197affe>] __msan_poison_alloca+0xfe/0x1a0
> [    6.882985]  [<0000000007c5827c>] start_kernel+0x70c/0xd50
> [    6.927454]  [<0000000000100036>] startup_continue+0x36/0x40
>
> Between trace_hardirqs_on() and `stosm __mask, 3` lockdep thinks that
> interrupts are on, but on the CPU they are still off. KMSAN
> instrumentation takes spinlocks, giving lockdep a chance to see and
> complain about this discrepancy.
>
> KMSAN instrumentation is inserted in order to poison the __mask
> variable. Disable instrumentation in the respective functions. They are
> very small and it's easy to see that no important metadata updates are
> lost because of this.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVfYNpMynQtXiKemoDy3LjH5Hn8N-VpzH6AGVZ3jDHPUQ%40mail.gmai=
l.com.
