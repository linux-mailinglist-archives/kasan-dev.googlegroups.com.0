Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBVPB2TXAKGQEWGGDJ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 148D2103A07
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 13:25:59 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id s9sf12402418oic.3
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 04:25:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574252757; cv=pass;
        d=google.com; s=arc-20160816;
        b=UQlP8trUkEKnUWuxQRkyX9hZH6hz3HUZkuFDih+PtKOADE1tBIYZ/bPTd0bGWJwz3Z
         qYTNwO7eR7hA5tno84XbTRWp/SHdFmGWKtHhGOmWknGX1Sr5tK0nlqC13o7ok6SO6EU6
         lqhActrhrdNAagTDAmnifDAeib5EADgh/DTRTkZGbrp8Bxe8wr+ndmoOOPTHjaTk1Ymv
         QyqAy8lhte+rNKRlg8kNdcjiSaWUDJqGsOtBONrwp/R+aHQUxavWlBHUkj0Jth9y9Gsq
         DflGJhjing2bVspk0UqTJtiZ740U+tQXVNTTuh7WPSk4yZnaXzmjXze5H2Myo+poAxDU
         Whjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k4FyX4L8jAZIXwV2bZb6RrDI3ywIbnL9xtGf9Bt1i4I=;
        b=ukV+XF2xcR0Dv8LoAACXUyPaHfOqp66m8srRmXISud5OQm1uFDGPIHsl+wEtitxRIX
         czTSCF9jjN0UOR7RUNBYOXf30vXPIGC2GyWBaMZhQ4lc6pm76gxJdxytqjMHjskuhsBt
         4xxgiECgomMKNtA4cpwTGDwNvNZDxs6L8ddw/SIDI7EzSAriRF7vDfaqt3dcQnwKbpGL
         lPpc03chV/lPd3xTaaYTD/VWvJKGWBJPlFSSOlnnbyIkhpR/veWwY/ejDrfZ6RQ5Ya8Z
         gdymeGZ/+i68VDdKatvqW9+0Q67w3Qnj57IW9oTgcKZVRhDwdKakbQnIs6ouRjqcK5Ho
         1LRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oYpO4a7o;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k4FyX4L8jAZIXwV2bZb6RrDI3ywIbnL9xtGf9Bt1i4I=;
        b=tA2AyA4M5dzWB5iRddF2UhiZTD4vI1mKhrBDJvXqyHpQ8sRw4IevOUyPfFKY/w15JY
         4jb2PYcqx6l23+ikLM4QynrTNjnv2VeElfz9zgnQwifoJalQOvmJoZDT5JA9Ph07mu1R
         NakjutI1N5H3tAtdudPRVtHyHuh+sRD/5hJ8QHxkVpOrXNw7C918A5wZd45GrsP2Qrag
         4HTOg/REwVNXYFN2V/kmzzJHTvtlDkvzEMC/1fd5TxH/YuCOm3WclBQQGl6E5X5T/rdL
         IbRisTOu3rQh/in7PqaAnKFLNDHHV5FyLmzmrbqJeD6Gw4ItV4HzfBBIc9ioq2dWGtWV
         XATw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k4FyX4L8jAZIXwV2bZb6RrDI3ywIbnL9xtGf9Bt1i4I=;
        b=nHBveN0LDDbisLnzw+Kp9bxXjxTsNa78ufWoov5/R9XBibDjmIPz3xosD9tjlXh5MF
         KUbEJ1DEO9wG9CBbf8W7/cK9WxbXCwMaUNLoupY4NKrk/Zvuuhw3rnIheR4mL2dKkr2r
         SwpdKpvEmmQAwgvKnRVu/PA8Fr2yzDRKjQaKrm+G51lJ0jR8dXcPt4KObPkt/YcnQn0s
         VtrLcz9JGSLsQ9kJskkryFU9nqUpMYFDNMBeVpoRVUrwWvZhuZlEvF6NMIyMcamG48bP
         QYC8ImNZv8chit6adKi6KsLufWhVwMzVUemRHgQ8gUtjFMTJ2VzzDuzL8b7CoA4Ls2MC
         Dc1w==
X-Gm-Message-State: APjAAAXazj5vTKf32zLpXqnyT29HJnPW+UtSipLRljkp30bquNfLMHgT
	XsCC1TNhitrazzcJK0etiSo=
X-Google-Smtp-Source: APXvYqxcEPG8IS2dqLKti1wjKyZbhziZieNw/CLFgOOiJNvFrD1rjlsIyxABsOhHww1E1HZNXMnSAg==
X-Received: by 2002:a9d:648f:: with SMTP id g15mr1819657otl.195.1574252757581;
        Wed, 20 Nov 2019 04:25:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d410:: with SMTP id l16ls315201oig.2.gmail; Wed, 20 Nov
 2019 04:25:57 -0800 (PST)
X-Received: by 2002:aca:62c6:: with SMTP id w189mr2638429oib.33.1574252757226;
        Wed, 20 Nov 2019 04:25:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574252757; cv=none;
        d=google.com; s=arc-20160816;
        b=arvTeeBS/BbHT+KigED67EDE++j1j3QcHla7QhKYZ7n1bpigD3KNG6Slzqc0QSPPkX
         9lToNvSHFdn/dpiXLF9UPiV6yF1s9aBZqmbw2zxi48ojilmA6adCvZmqTfWxyox5wW5t
         MixkiZtL0ZnLymEQvq+VKiYe7af47I8xqXuflvpsRZ4/Y3Teogba0UcnCRebv4QA87dY
         AwHkJPPcYpsXeZn/66L9VYMkI0cuRtxU0f0+0MCDc3KVKaH7vhdwPx8STgSBt3fXu/kN
         L54oNpXmrHLLqOKlyEjNOpiNFK6ecaxI4L6zZtL7IBo5euSditmqWmqIVBu0s75IdK3i
         ILbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OYgI0VLRNUN7kGlwtQOhcKfVKjsn5CpZCcyjwK+JBuU=;
        b=NlOF84sPUZVidgfh43ZNXmL8F2cxa6QB6Alu4SqPw9whW23wpHInx56nUmziaya94V
         EEdo7+LJFpYHQLtpGwVHldfHhE/zUQzwfHHeQ2jPL/NuWJdRG6v1SI4X0PNj20Wqgk3I
         lAW/mljcxJWd2d+kjlHko4Q89fYsHsA86CM0KEuhEp4AFQpnLkB7wt7B/e/kPKEJpW0o
         29CtshAU7KrDwgO43HwWX/4xjVmVNxaFAVSloPy6d/kB/xa7LVkD5D6IiC/7yPZU7mj5
         gYb/NBY2hIWSmYzYf9lVfmEMipAQcEoEquvowmgBhsuBTeKwSziBHPJMik/mhosjRWCB
         UsbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oYpO4a7o;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id p16si1686369ota.3.2019.11.20.04.25.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 04:25:57 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id m15so21011832otq.7
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 04:25:57 -0800 (PST)
X-Received: by 2002:a9d:7e8a:: with SMTP id m10mr1856077otp.180.1574252756578;
 Wed, 20 Nov 2019 04:25:56 -0800 (PST)
MIME-Version: 1.0
References: <20191120103613.63563-1-jannh@google.com> <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com> <20191120112408.GC2634@zn.tnic>
In-Reply-To: <20191120112408.GC2634@zn.tnic>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Nov 2019 13:25:30 +0100
Message-ID: <CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7=hzc+d=w@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
To: Borislav Petkov <bp@alien8.de>
Cc: Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oYpO4a7o;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Nov 20, 2019 at 12:24 PM Borislav Petkov <bp@alien8.de> wrote:
> On Wed, Nov 20, 2019 at 12:18:59PM +0100, Ingo Molnar wrote:
> > How was this maximum string length of '90' derived? In what way will
> > that have to change if someone changes the message?
>
> That was me counting the string length in a dirty patch in a previous
> thread. We probably should say why we decided for a certain length and
> maybe have a define for it.

Do you think something like this would be better?

char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez26RGztX7O9Ej5rbz2in0KBAEnj1ic5C-8ie7%3Dhzc%2Bd%3Dw%40mail.gmail.com.
