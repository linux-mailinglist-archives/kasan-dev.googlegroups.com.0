Return-Path: <kasan-dev+bncBCAP7WGUVIKBB54OSLCAMGQEUPQJIGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B76CDB12976
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 09:44:56 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-706ff7f3e4fsf56495736d6.3
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 00:44:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753515895; cv=pass;
        d=google.com; s=arc-20240605;
        b=TOflNlFEjIW6z4Uy1IZI/M4SZFeP9P9fYm99FSyGSH5u5+abUbjmKlrAMCZWSvD2Ok
         1w83G9YWyF4uyIkiXZsx5p7sOPcuQFP0r8susJX9DEKHV2Y1zvdWanWKgc8wGSC2DOVN
         uCS2KTFtBXh/wCVfxf7gOE+HxTX6YydXSA9DXJ8/l2c33/EG4uC7n489wF0r0AeTrru0
         c1mVZhadRG8vRv1RbXxtjLZe7F+5KJyAEktSX+VzdwJQlUTRYnD8epFbzlZ+44SJAlxq
         XQhqh0x0ev99JG8L4iazfo8/Wua0lA2I/QXOOL2Pe0KgdXRC32f4jj/rb9GUGosi1Xtp
         9vJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=hX+E9rDs/SFA1E6jUX3hPs6m+Ke8UsqGCJHCfm/dmO4=;
        fh=lpR6A/mhYaCal4mGI6Cd/YMEHQsVdlV+MBME9kLQqUo=;
        b=XxOmTREcdBxDl2U9eX3i8Zcn+sSfJs6HE7Na3j38TY7RHDbtOEszmy+2L0wmW13V0J
         EV9O4N1YrYnPGcnyiNo/CR4nrVXywPIrKJDPLWxr3MQk93ecnZ1zBWCqH7mZEsXtMsdR
         7IcEuju8Kz01Pn+GIXj8ZgXO5bSjhv6vR3SDWcRffm1MUiSpWUz9klFl8kqnaJBHM29h
         oNEPg0o9MM1Z8UZCKb9yIZA9m1HwjhrNDssUoQa4ocX6bZVykxfCKvZFtiIA27vdh+oi
         F45wNAvZ+ak3HLno2SIlKl0sftM0xQG9enNUByRwVDEJfy6EYgyseDATQYN8Fgg4IQqX
         pyOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753515895; x=1754120695; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hX+E9rDs/SFA1E6jUX3hPs6m+Ke8UsqGCJHCfm/dmO4=;
        b=KTqDT/AdkFt+FmweWXw5k3R9Ueu+fKS65ajL2YRyNBm3LNoceDijK+9Ep+aChR2Imn
         NxFzt786SzJcsDlOaQuVagMZQRrQ8mPzMz4lsiW3MIvmkN8+CF2FnZ3BHz40ZStH4pP3
         RMh2WReQzUxyNl8pTMvgzeKzI39+/wtRjnibKA/U7339Pj7HPgwToXkiTZVCsV9A6yUJ
         iomUjsH86pXbMgDXctNPuqwAweu6Ba4NWL/G9UJaHAkX6ka9iuqdBKbWqZKw6OoTOVTt
         U1t/YfhDIS/bwTAGkCb3GVGLrTcOlvqFya2Oby0bBvwUeEiggwASXbHrVB8BKQfMgswJ
         bzKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753515895; x=1754120695;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hX+E9rDs/SFA1E6jUX3hPs6m+Ke8UsqGCJHCfm/dmO4=;
        b=U8exx5qIQ8DdfybG7F0XvAmNGe4LwyZr7FvZdG6xULTwoeoiEs9VGuofO+eAy60lqs
         l/HzZgsI//j9QjgGxSdocl+RdFNsIRuzV5AXzJqDVP11MKkR1xDDx8KK8jP1E94XmqYV
         o4BGNHSjJoHwKlGSSMzPp1w1uqGKJDSnKvMWxrAKDsGRxtMTw8HlQRuqkxYizGe/Lp/4
         FPo/1y6X9LrLUTpvrZb5U6RuB3fOQdoSLrzSQ50rewEtxY4LFPxzg5PWWTC9vBl1Ps0V
         hn086AmPlzibcVQgESX5r80lHTTsS7Z+aqwVxREWmob4c+LnWtBZ0xFD1VmvWET1/Kii
         vnrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5LeOSUgf45Y/k6yTtV3KRUNQW9yiytiUrAf30qle2vILumdiuEBZYxtPy2tGPYOj2b+Xhig==@lfdr.de
X-Gm-Message-State: AOJu0Yz7Eo5nGnDfzdfsx+yiYTgXKdJkhi0ligHJ1LVqv9+2ah3+OYfX
	wKDKBGo7bhXL9frwNLRw8O/dSf4GdG7KoaVr7VAvMHAtXEk7WHNiFADB
X-Google-Smtp-Source: AGHT+IFKii/WVC6DCqNpwetgKB5rxf6+b79a/vy2Sj71QANvS5hReb66UEGlSFo9tw77ByFcYk6tkg==
X-Received: by 2002:a05:6214:1bcc:b0:707:765:13ef with SMTP id 6a1803df08f44-707206fc6d3mr55651046d6.15.1753515895427;
        Sat, 26 Jul 2025 00:44:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf/yqWSfbSb0b5ZtgUs2ScqU+M76o9PEqHuS51DmTTGSQ==
Received: by 2002:a05:6214:2f82:b0:6fb:4b71:4195 with SMTP id
 6a1803df08f44-7070d2a271fls36764366d6.2.-pod-prod-06-us; Sat, 26 Jul 2025
 00:44:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIJIxQPU9O1nj27xpkXh9uXjvKJloYj7aQIZLwCXPviHXuNuwp7PrfsmOLMRyMeGgKb0UOmuhni2M=@googlegroups.com
X-Received: by 2002:a05:6102:6d0:b0:4e5:abd3:626e with SMTP id ada2fe7eead31-4fa3ff8845bmr1946280137.24.1753515894342;
        Sat, 26 Jul 2025 00:44:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753515894; cv=none;
        d=google.com; s=arc-20240605;
        b=Y6ogx1drq7Hxy/ues8lIoBdOv+4hAyFZk/BEBcm0AczUF3Q0u8QlsMvAiUlPDCJPfH
         nY1aC0bcNw+jul2WgMw4KgnEYnfmhnLyLp6w2ON8Tk1yPDCzyN/xbVrJ+eK30JtILibB
         eDKbt7ePt8v0fPgNk07tovb/hg/+XT1v7lSxLUyZZ+TM988bajPTSqnm2hNxrROq/p/G
         lpWYBHG+QVU3j7z1DHjlOtacWc/hhhZAw1pHJNCkWwFuEog80xykLgDJUtqsLhPdiTxL
         MzhA55Gc2a1V9m4X0Xz0jFdt5NWAt9AncalPFmV+grMfp5/+bf2YT+i4413I9qKZ8KMR
         G8jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=UYAYgTbvtvlH1zyjrQJlllFP0LTtxc5fOVA93BJPWZo=;
        fh=o0GIY708cSfmj+n86SLU/FJlhZHvveRWX2MUfO2b+0Y=;
        b=R5HkYyxnoblaVj1rlule35fS677zOZi7Xhxe5cWIvSws7mNsgFBmwnYDwLRH5cJG2S
         kVHZio4LQiCjEfrOiUap8eYeNUfJpQLhuYmqW6Lk8mdiLlsxUTzvqnQngYxbB4BD5p4Z
         XaNOxoD/na5c1KtGPFztHquAQ5kywDhRNsu3TYmFDvCJQHvGnKgEe0rk004hj2Xv+FzE
         pgZWS9Y+F5jjgji+uWRH6FOYzcKdBBr4noG0H0AMwHV1hC3DTcbOQP+uTTIAH8al0fNK
         ci4PvbWLX6wtPDrHbIK5b/E76CAHucndLJJiVYA2E/dDaM4X1tctOCCI7OlORULg+voH
         XWNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4fa46bb4a46si105813137.0.2025.07.26.00.44.53
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 26 Jul 2025 00:44:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from www262.sakura.ne.jp (localhost [127.0.0.1])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 56Q7ifur087134;
	Sat, 26 Jul 2025 16:44:41 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 56Q7ifxh087130
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sat, 26 Jul 2025 16:44:41 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <77c582ad-471e-49b1-98f8-0addf2ca2bbb@I-love.SAKURA.ne.jp>
Date: Sat, 26 Jul 2025 16:44:42 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Yunseong Kim <ysk@kzalloc.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
        Yeoreum Yun <yeoreum.yun@arm.com>, Michelle Jin <shjy180909@gmail.com>,
        linux-kernel@vger.kernel.org, Alan Stern <stern@rowland.harvard.edu>,
        Thomas Gleixner
 <tglx@linutronix.de>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        stable@vger.kernel.org, kasan-dev@googlegroups.com,
        syzkaller@googlegroups.com, linux-usb@vger.kernel.org,
        linux-rt-devel@lists.linux.dev
References: <20250725201400.1078395-2-ysk@kzalloc.com>
 <2025072615-espresso-grandson-d510@gregkh>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <2025072615-espresso-grandson-d510@gregkh>
Content-Type: text/plain; charset="UTF-8"
X-Virus-Status: clean
X-Anti-Virus-Server: fsav401.rs.sakura.ne.jp
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2025/07/26 15:36, Greg Kroah-Hartman wrote:
> Why is this only a USB thing?  What is unique about it to trigger this
> issue?

I couldn't catch your question. But the answer could be that

  __usb_hcd_giveback_urb() is a function which is a USB thing

and

  kcov_remote_start_usb_softirq() is calling local_irq_save() despite CONFIG_PREEMPT_RT=y

as shown below.



static void __usb_hcd_giveback_urb(struct urb *urb)
{
  (...snipped...)
  kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum) {
    if (in_serving_softirq()) {
      local_irq_save(flags); // calling local_irq_save() is wrong if CONFIG_PREEMPT_RT=y
      kcov_remote_start_usb(id) {
        kcov_remote_start(id) {
          kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id)) {
            (...snipped...)
            local_lock_irqsave(&kcov_percpu_data.lock, flags) {
              __local_lock_irqsave(lock, flags) {
                #ifndef CONFIG_PREEMPT_RT
                  https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/local_lock_internal.h#L125
                #else
                  https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/local_lock_internal.h#L235 // not calling local_irq_save(flags)
                #endif
              }
            }
            (...snipped...)
            spin_lock(&kcov_remote_lock) {
              #ifndef CONFIG_PREEMPT_RT
                https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/spinlock.h#L351
              #else
                https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/spinlock_rt.h#L42 // mapped to rt_mutex which might sleep
              #endif
            }
            (...snipped...)
          }
        }
      }
    }
  }
  (...snipped...)
}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/77c582ad-471e-49b1-98f8-0addf2ca2bbb%40I-love.SAKURA.ne.jp.
