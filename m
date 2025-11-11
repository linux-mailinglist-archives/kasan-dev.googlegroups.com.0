Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2EIZTEAMGQERNCG4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ECEEC4CB71
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:39:54 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-7a43210187csf3789552b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:39:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762853993; cv=pass;
        d=google.com; s=arc-20240605;
        b=W2WfM/8pK79d1HxBqNld3+FgOqBZBXvcBZd457K4FGnMXPkg1N4pxogdWVxn42S3be
         GOehLv2vJRexGFGWV0MOBBR+dpkSPqjm0vMCaRsadjpo12Vq9fMUIYIUcP6wiB9JL/n2
         hMY1KTpoN2GVj9HKp21OhPZ4lRTbxNGUP9XTGnMFOmXn+12ZZWXjVkUR0+CJqbAU1ovU
         NrtZMMGdHpy2O3amBfOOQ9ailCax5vzWdv9HgdI3NoUOayrMM9GL5sL5gfhcSDZ6CqJ5
         cfOIdkCfIQyfi/JyPRQ9EJc5rA6DaHDXyQeosIZf+RrU+HGfgM5G2YasRdF/q8sN7MnW
         lhjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=15RY08qEbB4SVPzPN62fkizB6qOerJIg59a1CjB88P8=;
        fh=iYctmmOWIX6AsL7qoO47cAMc8tXSTwq7/zrizqyt3ZE=;
        b=SpsbM8UFSe5AKjTIczZfdAOs+nEHXj0MllIBDU134jJ/t5PFtgFtJIGxQdASZfCC+7
         D+T+QAa7pxOCryPvhtBoBxGSjyhGE7DPYIpOn4othZKPA1UUGeDxa3MX9gc5I4QKSi71
         g8oK414alctkGL/QnjBoTpULc1yLH+H+weybgy5CRlk9TY2LCNcaQ0H/758rfS5ryvzB
         3glvnHTu3fay+4WuzC1wmeM9sVgWEnxedyneENq/Y02rKxceeClzkkYvKWRXSwwgfG80
         IQ5xW9U2BbqffGsWL/bnie7g11Ho2KrpoVXAbzsChL5JnKn3yCo4Stbdy017+8oMK0Sa
         sWLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xnymd6LA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762853993; x=1763458793; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=15RY08qEbB4SVPzPN62fkizB6qOerJIg59a1CjB88P8=;
        b=BE07z+QzRidssqL7hgF3hQW4Ogyz2vps3eNoyvpXPOsxgmVUCgyZ61hE5sEHx3is4P
         NHpdfcQ/hFqMBfUcm4wieZkl1vcDyMkKs6A5FPJYxyvpXG3tFjO8Q/EavD2iByNzyhMz
         Re5kK5zLKvv9y7hUG/unKGcJW1XwrAKKBngWWRm4XeQOn9U14Sb5bIoYaQ/XqXjnn2P2
         DD3uksjegZcO3XTXPpHApjprLTDMZBxZ792smrfyQ3CyDxvILk+yM15cB/CvcFqmafIS
         fBHpvJ9hyLxF9xf/Ffp+J0cEL1xQCXF0AZ97biLOmKjwhAlSbh8tDOkMAR7lzPfbDCp0
         xDoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762853993; x=1763458793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=15RY08qEbB4SVPzPN62fkizB6qOerJIg59a1CjB88P8=;
        b=ELdfuMKlmAOpZf9zZ7ZqeEstibQZrwNv5TV87UZqN6dy1mQExZzg0bfuJmf0+33Vlv
         hFRCGhB5YXsI4vn8VRw4/FdtN/wkyo7BXjsHqz1NUpVuQN+bk5lpfdyd1883tlQRBzkf
         Y2JpAIxd8Ehmx+gL0IIQNC/bqPDsOGr6lnWCO0W4u+a9ikt0S0TfcxtONawAC52deSu7
         MOMEW7RNuaSXNX7PWIO29Kc6dWc6iM0pgKxxpBd+g1B4lA5rXEIfPC1erJB498RMzfkD
         V+fht2+o/Z3Ur/4bsZ0oziA7a3CWBXvHc6VQpA1qijsZhKXVxTh4bvc2LaNVTMjU8gm2
         my5Q==
X-Forwarded-Encrypted: i=2; AJvYcCWBRrWz9NovftHilMxQwgIV4eJ1+yssmhgKK/zsbO8qjckPLtafuHyMc69TAaLv9G7ffLceOw==@lfdr.de
X-Gm-Message-State: AOJu0Yy1wjn5cSzL7JLW+tPGMKmNFxITxfyGrI4h8T07FHAnrxcw3+zP
	1Ql0T5c7lZb9Okxq+6xb859SMvb1TSqbGZX6gpI/+klHG4Al4F6EopQS
X-Google-Smtp-Source: AGHT+IE6lj++yhyCOB6a3p1tHGF2IBIm/FM+fY55XeWoWQeMmAA8q6QE+67Hko99iiy2kVrLCY099A==
X-Received: by 2002:a05:6a00:1a93:b0:7ab:6fdb:1d1f with SMTP id d2e1a72fcca58-7b22727c5c2mr14868588b3a.29.1762853992727;
        Tue, 11 Nov 2025 01:39:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZwDAuvvtdYePu6IN8WAdI/UyeONve0PA5nQgfcVvjyWA=="
Received: by 2002:a05:6a00:93c6:b0:7ac:a138:8068 with SMTP id
 d2e1a72fcca58-7af7cf0202bls4724064b3a.2.-pod-prod-02-us; Tue, 11 Nov 2025
 01:39:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKmwPb+HsUI/js7hKVx9Cs/s4QQwz1eRjw+XE/0/SucG0dm6pKf+NTp0S6G3M6R+/7P7f1RzW3Qoo=@googlegroups.com
X-Received: by 2002:a05:6a20:d704:b0:34f:1c92:769 with SMTP id adf61e73a8af0-353a1bdfd4bmr13585634637.16.1762853991255;
        Tue, 11 Nov 2025 01:39:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762853991; cv=none;
        d=google.com; s=arc-20240605;
        b=lIXn4q7h83wohJ3KO3i5oemuKmhgtzG/gKKr2E959ibY/z+EHOGzozEzplT3Psf259
         7agQQzZ+oCEvNQqwVKqTGLJrCK2FmDRl1s+K+S1jbmYXCTrTZCVILoLXBSUmgoXqleqV
         nNz9kIFOx3xrni7Lgh6I5yH4fOhFdKCi37KaRsFuz7hRAH+vhgs0Vt3BCa9JPku0WWwB
         Yb1ZQUVBVcR5+kMBDsBL3C05wt/HCjAlKIfTulrFDP9RGWpRN0zhBAIxOw4ldbWnjqXY
         vYsIEIsQMezzC0X63Tg+4fAAIo8Y+nEgTXHuJHjOuHFAOEm0hBARpX7R2mTatM6nR8nw
         3/vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x27CBOBuvs19lllL/4Ne+a54Yz+5/uzP3YpUzWY+JnY=;
        fh=yZzbO/iipThK0McPAKJLtnfyqroR6En+uUp6jgr0Gf8=;
        b=Exf9KcVCbP/3+O2jlwVwAvWUt3u6rBRdG1tV5rTQ2EF24GJTvzU8aNkXXjGy7TrWge
         HsKr/UauZF9wkYh9L3FSNPREUTqA1pk2ypNutYk5Tg8heb8a6POdysh/8ErpEcGtsYB4
         RxXz5secuzamWpfPGs2NbIASmjrPgl8Rzdenda+awWrWOhEtVgV75nCgOXZ4qMqM2neb
         rIqrpzCce8SXHTn2sBe7ylTFD4mcO0dzxsfQ4z0uFhSkPgToa6kBQx+m/nzsja5Ue8Nc
         iVesAP3eEd7rBtTSxiBeRMvSzS8352RjikRDbKOG7TFUE0k5WJq0kmRFf616SOeTI26u
         IYQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xnymd6LA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-ba8f0d1522asi412605a12.0.2025.11.11.01.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:39:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-343684a06b2so2885552a91.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:39:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXvi4nXbistOgmMqeEkjRpDuITxZESQUcY8V5I6yJlZKPEUtphzjpfvzlFymgKQghA1BUcJCsqa1uU=@googlegroups.com
X-Gm-Gg: ASbGncv0JyOaWZ2K7BhS2R3gT9SzSMKsgZHjRQ+7J19bQ9mFlLWLTTkC/wX8PbB0DXx
	Y8Rek4ifQbxZWTE+obLO9lehu9nAlOIJfLQstfuLt9twTi2r0OWd77V1m5bs7ks+Nc6yA0zZlRP
	CfFbL+qxK5wEgq3rL70uU52HlL6E1/ErYL9c0h5rLTFYhcS3hWgTVLmD5T2Od5+5Pz7nwzYAmHM
	xeiySP3IBk6ivVIr3erBUXY7cLwN6NOibmkl4aVlZB9qeanmdVJTkHeJHu5GCuzcyD2MbazLBSp
	6yh2Ar4voHlh607cJa7gDg5yuOnTw0hgB0QV
X-Received: by 2002:a17:90b:2f8b:b0:340:ad5e:c9 with SMTP id
 98e67ed59e1d1-3436cb9f0a4mr17438597a91.16.1762853990547; Tue, 11 Nov 2025
 01:39:50 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <ab71a0af700c8b83b51a7174fb6fd297e9b5f1ee.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <ab71a0af700c8b83b51a7174fb6fd297e9b5f1ee.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:39:12 +0100
X-Gm-Features: AWmQ_bn-DpseVZlfA_JkC1KeMe_i9gWzENoYdJOcpoJ15BxyTxVZhbSiKbweC94
Message-ID: <CAG_fn=XyQ5Mc_ZvsibN4K0r70xfDAkhPqUJgtojVRcgTt-q0WQ@mail.gmail.com>
Subject: Re: [PATCH v6 03/18] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xnymd6LA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b00849ea8ffd..952ade776e51 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -61,8 +61,14 @@ int kasan_populate_early_shadow(const void *shadow_start,
>  #ifndef kasan_mem_to_shadow
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
> -       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> -               + KASAN_SHADOW_OFFSET;
> +       void *scaled;
> +
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               scaled = (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT);
> +       else
> +               scaled = (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIFT);
> +
> +       return KASAN_SHADOW_OFFSET + scaled;
>  }
>  #endif

As Marco pointed out, this part is reverted in Patch 17. Any reason to do that?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXyQ5Mc_ZvsibN4K0r70xfDAkhPqUJgtojVRcgTt-q0WQ%40mail.gmail.com.
