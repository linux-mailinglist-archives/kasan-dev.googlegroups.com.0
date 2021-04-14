Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBHUR3KBQMGQEFYTJENQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 50C1635ED0F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 08:15:59 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id d27-20020ac25edb0000b02901a794d2adbfsf370912lfq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Apr 2021 23:15:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618380958; cv=pass;
        d=google.com; s=arc-20160816;
        b=dq7LnuCWwmu9tWuOUOz0pDlogoEGm2w7oBjh4cTz5uIPFrTShlffJPt+AEOdiSB1x/
         dd9BDq8/A7QWogsBGUVhxfGdzi5Lh1A59jbWdENnPqgPZUi+ub1B/siGa/moW1e6Jc2n
         x4k7Pef+LJeBGk5/WclTFmq5pEixg4GT18gkXHc4IyZeHbZz8V8+cehLcjkq3a9SRuMb
         njRdnOuzv2mn76AA/adyjAuUPbs6dOmRLwz8kHLkgVc/ba1xWVlC0TbprtFscBcpvhQ3
         5jqB5X1XHGGcdBQPhuBU5IV2lt4wGfzHa9RP3mZ8q52l8pqc5472pUpMWJrgzG2fDq0r
         mfEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=dixhiqP80xBG32O8lu16dMBC32uPnJCFJ3Qsh/oW0/A=;
        b=cZw7ySNCe4BW+0xneG/Nw9Kz38T/aXOcRIW2Ri8Pdo7x0LXEBZnm8aBw8MFcnDyulW
         79HDvBvb5eO/TrHPpCZsJz31T7KMZpyvvdi8X+mUVYhXyS5k9r3F/1HnKWc1X0drlVPP
         Z8Bi2uCndF8UD8L7PIjQJLS7tUmxDqCsh8DLq6iJxtAd9rhcpDZ5/YixQO7/D31sfM3E
         Gp78nmK4LddDgQZoGQPjP7rULuwwWDupN9STEjk93OmPybF84osShWLtCX0pLWsU65UJ
         JJZ3NiURyjUSEXXduy9V5/PAzN6oGrvuMVZ2HazDLeqe7gc+tFy4EHynqHMn8icVMmoH
         P1eA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=kGoeBbSa;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dixhiqP80xBG32O8lu16dMBC32uPnJCFJ3Qsh/oW0/A=;
        b=jSapR1RMSytgmY51mG58eIW5DxHjTetKRUY3dW7TvZq7Z06j7APYGTU5DPJh9vMkl/
         VUpmqyc0cYcw6lNfHaqiCBWDtKvDH1mUiIiEO24e573e5nslOOo3J8HnnIDwa1ND3uuj
         GMiqTCEuOTsz/hn/1xbNhVePvvvD0T3tZQcnKXV6eEvpGRT8RYX3YrsFkdesNPDhKPMV
         8kcJ7rZ8c/fCSHdZV76uWS0/xel1blNdexJvGpO5QpXQyaAJIoqo1RiHRGIhgSPDS2ud
         dydJQ6W2Utt0XUhDA8KYz3TadOTLqSMh5aQ01eDQtfiZfmI6vU9/IDBk2yrtYgfqp07j
         dqnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dixhiqP80xBG32O8lu16dMBC32uPnJCFJ3Qsh/oW0/A=;
        b=UC4Rxuill/iUUdVHvox9Da9jIGrm/oBLEKB3UXym5IPehGw710lOCHkkgoCU5gSnAn
         in5yV2YmIzoekfxbjIz9uF8N1++Xo485EjIGP74W/hqT3MUFrEwzi7nP5s7Z5UBLUdcd
         VHciLCJ5xiHeJCzcEhC0DoQwbVHefBXbXWmjH5t8y2PdyCwh4PH0Mut3b6anegUwIdHt
         cF2aBOI9jP9lMLtfoIS5mbThMAR9JEWoZ7YAXkl8LkX0hniabwlRY9kHoJ8ShqdTIRDV
         m7ENkVpIT64kuv0Eb/d/402B9ZdZiqgoQAyYzKYEQLPB+h1jKGfDP24SKyDN6faUuJ/X
         JKGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YX4aw+t51k/5/aaNLjDmHQtHeS5Y5jYFspY6Ay9WyNwzjOwCu
	QOyotbZmdccfEAwajvJEcNo=
X-Google-Smtp-Source: ABdhPJwLHrJmY74bQ+575V+WM9dobPIi8Drzr1v5guAdkGAKfs6mc5Y5tOf7ujfT2X8YYbU4WJllyQ==
X-Received: by 2002:a2e:968c:: with SMTP id q12mr22452495lji.317.1618380958797;
        Tue, 13 Apr 2021 23:15:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:48c6:: with SMTP id v189ls1138240lfa.0.gmail; Tue, 13
 Apr 2021 23:15:57 -0700 (PDT)
X-Received: by 2002:ac2:568f:: with SMTP id 15mr24730768lfr.216.1618380957777;
        Tue, 13 Apr 2021 23:15:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618380957; cv=none;
        d=google.com; s=arc-20160816;
        b=y+9P+1ZhiFQ4o2A7AGznneoULWN7f6I+PyVC3ckp0O3sfIID7fXPRJmbBGgcDoALMg
         7znHGh5E6wqJcQZcud3GewzWooWRxjTHz80n8yp4ZceE2gcG0GVzo+M73iao6dayzxkV
         m5U6SdA+uySro/567Guv/W+y5A4D0wjR1NK0hmxKmoXm1gi0MjDX4MXTxFHe0UfelotB
         AoXWmNaBygxSY4GbEnFiuDYJv0bhWz/5yLwyIx8r3ZOSgND0VeEhJBtZ1dRUpq/LROWx
         349uYvT+IBtLwhgq9xMO15p7j2K2TA8GM6MiP2Z8i2Wk5YYyrrsNZUD6FjSg19RvB34Y
         2hlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=fCT7a3DwEDpTvCAcXZFVCXe+sSIexbpwUL2TbgQsx0s=;
        b=zyO7H7PGf82mz1gskDEYYD0Bu6fS36SC4gL3ObAHoG0rVVn+5NMoLkowqAoU/2K2k1
         VvDyVOrOxYXfHK5GxmnKp+kDxab3k5h4ni2TDOVZUuh9NMUhDPlZil9mjNLBiBbemkEB
         sQKik81oY7TZsU7sNn/BzGTyKcNWFwPpw2iAtJrF+DhBGa1iWpryYcUnjBNx9UMTgK4N
         d43Fd4+istwL1HJjPQox4+Rzl2FxrPf1bWW99butKbUZ3kdoxmFLOZwS3hsG4aEhl+aC
         7D0bUfDkfBCCe8Xa77kqLckRHkFVLq7oIOXUQ0d/5mzvFaDnwnxK34UjNB51cSloiGpE
         qn+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=kGoeBbSa;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.17.20])
        by gmr-mx.google.com with ESMTPS id w18si200315lft.10.2021.04.13.23.15.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Apr 2021 23:15:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted sender) client-ip=212.227.17.20;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([185.191.216.50]) by mail.gmx.net (mrgmx104
 [212.227.17.168]) with ESMTPSA (Nemesis) id 1MQvD5-1l9HSv0MjP-00O1tK; Wed, 14
 Apr 2021 08:15:54 +0200
Message-ID: <a262b57875cf894020df9b3aa84030e2080ad187.camel@gmx.de>
Subject: Re: Question on KASAN calltrace record in RT
From: Mike Galbraith <efault@gmx.de>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Zhang, Qiang" <Qiang.Zhang@windriver.com>, Andrew Halaney
	 <ahalaney@redhat.com>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"ryabinin.a.a@gmail.com"
	 <ryabinin.a.a@gmail.com>, "akpm@linux-foundation.org"
	 <akpm@linux-foundation.org>, "linux-kernel@vger.kernel.org"
	 <linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	 <kasan-dev@googlegroups.com>
Date: Wed, 14 Apr 2021 08:15:53 +0200
In-Reply-To: <CACT4Y+bVkBscD+Ggp6oQm3LbyiMVmwaaX20fQJLHobg6_z4VzQ@mail.gmail.com>
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
	 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
	 <182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
	 <CACT4Y+bVkBscD+Ggp6oQm3LbyiMVmwaaX20fQJLHobg6_z4VzQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4
MIME-Version: 1.0
X-Provags-ID: V03:K1:i2oTji6pkK7Awnn4kp8awBkagqnDehpwQ19loaFFTEDOWWzpnJT
 5ZWePAPbDr4rTHVpYVUUBYlMAKHS6+2sdX7n1tdPxczJZz8mzCKpkoxzCe7SWM/50iSywXK
 RH+YSrCdoOHBhEZ9MRZu3dJKn6zt9yAYMAWf3yTAZ4J5yi6w59Stoy+3HZ0PutFJUNeI8g+
 PceWxcmskbS47vHR1NR0A==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:d0fpSXM5V8w=:DBY15R1nVlW7LxOLFEPwLs
 UREHxo4fBskbInhck33ZUBkKQdD0vRU0gjuSKhx2B3cgiTI3SV6Er/3ZhFIgZlyTcvwIbUCOz
 lnHDE10fPuKpJyCsIoN5bd6Cs2IAoTJByLtufFeY+/YnMnA+YMPv8uxzuesxiuFqjSbSS8lyO
 B1uqZc0SF3s7xp3ixbFph8mCq1KxSGaStEeEwtgIx0J57bY85dMhR6UFaPHUTtuGv4pxBz0it
 ThXrI0/n6as1AWVOTmEI2hkLDSh3wMmb3rcMwI3ulj9k1XCCw3PtkrTcOtyLp04gTvNn3kNBa
 +ZGO4Ib0lFpyHneqmA/vLy+LY5u8oBeeYHRHvVm2TS6g1Pi/VIPSh1lTd21aKQ2d31aY7AS/O
 OHKtphiOQEtNn/SeapMt6q9kfIXeXnXLPzeY55CKq6WgN8Wp4/+KBbueAufhHHSissdFVJ5rP
 Ad7v+NqxWF5fkVlqMQpIou147d9Oh+4mliH8Hj0opjX9MU+W0hpn0RbgjiLUYu7vGfCz61+Fv
 vUwc92f2tXBZv5Gd4LqOACDpDBI5m3S+1Cpb5t/N0TBrpD4aze83LL5ZIjw3ECmDcMqpRCdvo
 Tp57EcGXefPGV14+ErR4hIj3traBLNLIw7ucgO8AHbpETHS/GfC+LnbJYA4WE7NqlLp4CUdNO
 HAXj6TdWpHW0uAdOK1U4gMnXo/FBHCCYCxwuIsXiQoAB2aWUd+r3nKD6L76lpwxFu2elozIR6
 57PMDNI0xc3iA2QAoHFBKzuvBkt76phX5IBor7L/yjOdoheBnN9Lzx7FIsSxBli0cFKmGVbhL
 6X4N49j3erCH2vTuV1GvJtE0VBwqzauzJy+Jjldmug9BJKJEJgJZGs/fjyc5E2rX727gtdPy4
 5BaXrpFCMvn+f8r4P5xYpKtT+Suz+0I32a2yG0C0FFKibLUTD6cAtl2nlg0F1qRuEbe7KZRsp
 G/lP2w6vlI7HHIK7lYrLzdpcY3EOPiaHD6Bnx0+aAKH8cutZSlzPWVANdCg748YZdbP/ihiBM
 HiSRMEkevol7wFeengVrkC8nIBIBgcDPIyChaQKA/re8Zjc+VRCbGP1gEzKFw0i/MbXUj5QUw
 pYoBrS4v3T40HXvwvfm3JBm8wjEwgS9HXZWa21b9cvLMqxj6DFXDqvBMs/94eBg6LQVe4dvXV
 R+v5deDlKTUkSCh604hAC/anoJMeOoRjI5g0rN79RqScYNhpCr1YKO14vtywz5Gt9eNSg=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=kGoeBbSa;       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.17.20 as permitted
 sender) smtp.mailfrom=efault@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On Wed, 2021-04-14 at 07:26 +0200, Dmitry Vyukov wrote:
> On Wed, Apr 14, 2021 at 6:00 AM Mike Galbraith <efault@gmx.de> wrote:
>
> > [    0.692437] BUG: sleeping function called from invalid context at kernel/locking/rtmutex.c:943
> > [    0.692439] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name: swapper/0
> > [    0.692442] Preemption disabled at:
> > [    0.692443] [<ffffffff811a1510>] on_each_cpu_cond_mask+0x30/0xb0
> > [    0.692451] CPU: 5 PID: 1 Comm: swapper/0 Not tainted 5.12.0.g2afefec-tip-rt #5
> > [    0.692454] Hardware name: MEDION MS-7848/MS-7848, BIOS M7848W08.20C 09/23/2013
> > [    0.692456] Call Trace:
> > [    0.692458]  ? on_each_cpu_cond_mask+0x30/0xb0
> > [    0.692462]  dump_stack+0x8a/0xb5
> > [    0.692467]  ___might_sleep.cold+0xfe/0x112
> > [    0.692471]  rt_spin_lock+0x1c/0x60
>
> HI Mike,
>
> If freeing pages from smp_call_function is not OK, then perhaps we
> need just to collect the objects to be freed to the task/CPU that
> executes kasan_quarantine_remove_cache and it will free them (we know
> it can free objects).

Yeah, RT will have to shove freeing into preemptible context.

> >
> > [   15.428008] ==================================================================
> > [   15.428011] BUG: KASAN: vmalloc-out-of-bounds in crash_setup_memmap_entries+0x17e/0x3a0
>
> This looks like a genuine kernel bug on first glance. I think it needs
> to be fixed rather than ignored.

I figured KASAN probably knew what it was talking about, I just wanted
it to either go find something shiny or leave lockdep the heck alone.

	-Mike

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a262b57875cf894020df9b3aa84030e2080ad187.camel%40gmx.de.
