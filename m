Return-Path: <kasan-dev+bncBAABBGWS5XEAMGQENIEBPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1127EC65B68
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 19:27:41 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-65742f8c565sf3839299eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 10:27:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763404059; cv=pass;
        d=google.com; s=arc-20240605;
        b=dUhhqrFyHrknedh2Rc3XMQNgu47dw8N9cSp8xTxO7uyDMIghy9T70OfRD3c86F41fp
         aKnjufrRXJ9k9yT1u1Ak0znuAriSj7zX6kZhMw8wiNy1YeNyY8oXDpaLPutk9T3aRSkZ
         x3tY4zeQ4eLvDDz/xnBGhFWUShwH/tVO/TO5Q4TwCEjyVXjHxVADnnbLFjsZoC6+OSi3
         tlGQkEYrh7WfJ/ZtOjn2CaxZnd2ffYlaAM9r5yZOasDfzx8XzmHceaipY3NWRqMSOejv
         gCkHXca+VqtFuo0UDZMW0uCsXo9Ldx/QkajRwF5tcrmDhNAN2cKnGYBhPjo2HR+BDxCL
         BcdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=5PbYEvxeCxVrar+QqtXw/P6/jMt4HCm3/fZgwN+Idqo=;
        fh=reVw7he+69f3kOEvaCNQWO6YqejTpvrCQF8XNVoG9H8=;
        b=kCA2IYCLrVLGcWvKOnIrEqqAGRUH8t+4tQdft51TylwouOGc+wbMrAzn8mJsV6v1gA
         mJ9n80svWL+TYDahLadCHbFmoqSxSA3fI0yhwFJwIwKwNV6cqiCiMNhO12j1OlFkDrWe
         b6fbzHb0yDfm//uVKKf8saOcIIX8/4OlJrw98vfjPRuxYfdyfEeXL2ylBMO83GAZaRIK
         +szMDAGNx781K1sp9luL9Zp6HOpL8RxBmzat1DqBLArhYjCRdtFJypOk8zChQvyVZe2c
         YOfoVa24H4oy85+EOugPYp/YCj6Rdi0qKb3H12heF9NM/GP1wSNnX7RZrkZCeWDCy4Aa
         Bi7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=DweFroUb;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763404059; x=1764008859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=5PbYEvxeCxVrar+QqtXw/P6/jMt4HCm3/fZgwN+Idqo=;
        b=EGdh456Xkq5WzS87CWZBu9UpGwWtyAyv+26SfZfbS9C5U5pbKYQwAkHY1Mppi+C9XU
         eBGoad+DntLmJC5lrzpZYDPzaYF6vRK5tBmqC1nO8uB+ClH10l7xy8PXm1tq+rLWItdE
         OBml82+da3EnoYHHksl8z6+lbStaSjk9zsSNgJBHMy0L3uvkJFivJKs/oGWvWOb2mfmy
         VyHXwBl+34OSwbk1yuz2JY/j02Flynmef6uhhQToqz2L4n+qusYg670ca8ZkmYL+9Uja
         5926ZgVfYKmjDKifBhYQFPGnIm7vUuXE1esT7s08gS/PfcbiF0JboNGMGGvT65smo9jb
         V/5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763404059; x=1764008859;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5PbYEvxeCxVrar+QqtXw/P6/jMt4HCm3/fZgwN+Idqo=;
        b=UvpKkO5ClDXgmj04fb2GonS6o2wtkn/ghVpwOtAJOFiu/+J8WIsRDnQ798k5CZxGWA
         +txhAdrA28dxzqjBngA1Pe0ah0ZoO7FPCpVN/994UEWXHQuoG3vFPQd7O0JXZfQQkZhU
         fVKeq2vRZclz3Vqi8i8mJcGab7RpEK4YyhEV4ROMKPnLLrA8qRWnwEEJ+Rm+MT3Aaczx
         2evaXClOkBpyOt6w3Pc9wdmNZcGdu6pL+ggUbhyYvlFq/R3IHTeqvMhW43KyzzVEwXSf
         8Jc2s3RsmYiJ1RktHIDOS6aYmcyotvm0W2PWa57sPJApjDEVnV19Ry4rWQCRSGBTakL7
         dbSQ==
X-Forwarded-Encrypted: i=2; AJvYcCXDEm7UBdI3SEbcD2zCIYM0lv1IyJRiRfZLGjzHs18Vt8SmmJd9RuAWBVyVFxsRtnOyurBKUA==@lfdr.de
X-Gm-Message-State: AOJu0YxF3LP1tQf5Vguf+ggb8OvhP51hL0bICmLWlgjQzAf1hC8kKuWx
	ONtf/GqNRPYiSFM+x8aqnl/vzsYUqBLgAwZDOplcNjYjlIhL3gTyvS8a
X-Google-Smtp-Source: AGHT+IGDu5n+K2ahzMm6FuN66yFOshNV8CmXVS0K6RQ1mz8mkExmUmFtvI6qohfM2h5qo03BDdsBTw==
X-Received: by 2002:a05:6808:4482:b0:44f:e912:eaa3 with SMTP id 5614622812f47-450974e7fb4mr5540706b6e.32.1763404059211;
        Mon, 17 Nov 2025 10:27:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z22ponopoexHzfgXFcBtRYvMc7XtFIsJ4lKDQ0F9eSgQ=="
Received: by 2002:a05:6870:6007:20b0:3e8:4817:7a50 with SMTP id
 586e51a60fabf-3e84b7b0a89ls287191fac.0.-pod-prod-05-us; Mon, 17 Nov 2025
 10:27:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWiePOqhAbhtd0eNhUBQXhplxmpYSZNmFRs3C3pU6eN5/U2o9u1Wh+RcNUZVL/hePUzSUOi65WYpl8=@googlegroups.com
X-Received: by 2002:a05:6870:4008:b0:3ec:31a6:8b77 with SMTP id 586e51a60fabf-3ec31a6db0bmr2641421fac.9.1763404058472;
        Mon, 17 Nov 2025 10:27:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763404058; cv=none;
        d=google.com; s=arc-20240605;
        b=eBJekj5xZx8DdVBFK2KkZjY1TmQFKNxlbOZKlpSJbp3lFf2zqKtGeKQaeFgediseaA
         5LY92t4E+NF6erhVp2JsyM+sgKYbXLjQ0GPaw0jO6luNa8CEcj0CPG6DFSxlyFcl9rhk
         bVkWV2U4pF0ooqdhdZUt/RRpQiZOrW3xjc328iocN4mNKsGmsDr5JOfFx3PySLgByzG8
         4hpOfHV46hkz1FNK49IH2OxsqNlAq1BILUY3E+bsbmNYrwIkWw4r5EgF9ygHOnJqLQAO
         RvhmFHPZyhPuyNr5Icf+WF+O8HJnrYqDH5/7W3q/D6pUeFO7EjNz/DHLPuKP6LYQyRJN
         Qk6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=GhZV33r+RQPxcvac5lYHFWgWQCGcX9mvWrodK8gvvLc=;
        fh=k/v3HmGt1ClsgCYHhLlDuddeI/n3RsPAzSnvJM/IeI0=;
        b=bW9whjhP5u9CodS4jSNlLFZHxfEjSQkxgSayU2pJMhtf336cGvldjWC4EtomFwcIiz
         99a7d/znihjPfoG9mgos4WXqONGRLJOMSP4uzsYMnqZiDj5DK+dExeXhBhRtdsAMTTmy
         Oud+qfPzofbRkqrtKOVgM+J8jx3+JvDatVLxYTpkhKfLid/6UbpEWlp3i0X9AdL1qWDs
         i+/YG+ZZd+BZOBApJKW1FSVdrr57jkuUtWgUAdfvxLYOaCxcrRCeazOCdcAXKJbcOmoG
         ybFGsb0gjyhL2RUrxC2gGe/1/JaTFrW7To2h6ye4MeEHR/5CbO070Hop6/vMmFZL5Wd2
         YXpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=DweFroUb;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3e852d8960dsi393913fac.1.2025.11.17.10.27.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 10:27:38 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Mon, 17 Nov 2025 18:27:30 +0000
To: Alexander Potapenko <glider@google.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 03/18] kasan: sw_tags: Use arithmetic shift for shadow computation
Message-ID: <zxn3unp5foytltq6xpzqmsuijaargjuigcu47fdvlhpgyvwfj4@zwcnws34hjfw>
In-Reply-To: <CAG_fn=XyQ5Mc_ZvsibN4K0r70xfDAkhPqUJgtojVRcgTt-q0WQ@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <ab71a0af700c8b83b51a7174fb6fd297e9b5f1ee.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=XyQ5Mc_ZvsibN4K0r70xfDAkhPqUJgtojVRcgTt-q0WQ@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 6ca281a9780caa8602cb87e0c0e4e958f247dc5c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=DweFroUb;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-11-11 at 10:39:12 +0100, Alexander Potapenko wrote:
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index b00849ea8ffd..952ade776e51 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -61,8 +61,14 @@ int kasan_populate_early_shadow(const void *shadow_start,
>>  #ifndef kasan_mem_to_shadow
>>  static inline void *kasan_mem_to_shadow(const void *addr)
>>  {
>> -       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>> -               + KASAN_SHADOW_OFFSET;
>> +       void *scaled;
>> +
>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>> +               scaled = (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT);
>> +       else
>> +               scaled = (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIFT);
>> +
>> +       return KASAN_SHADOW_OFFSET + scaled;
>>  }
>>  #endif
>
>As Marco pointed out, this part is reverted in Patch 17. Any reason to do that?

I hope I was able to answer that in my reply to Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/zxn3unp5foytltq6xpzqmsuijaargjuigcu47fdvlhpgyvwfj4%40zwcnws34hjfw.
