Return-Path: <kasan-dev+bncBDLKPY4HVQKBB65I57BAMGQER3AQMGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 51E81AE802A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 12:50:39 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-450d6768d4dsf41241285e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 03:50:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750848636; cv=pass;
        d=google.com; s=arc-20240605;
        b=eh50LPOHPrC1meKAtn7L3EsqAka2ooqZdQGbGR7bRTzzdDTlhqEK6JyNQQDsB7U8Fq
         gqxEd36vdpaNJaLQoN4DNgkmUJyMtNV72s2dEhph5vsB4/CgOc+bdM3YyU8le7VC6vRX
         zP5gJCXxkLs9NTKD46d0mDHqQuvudDX/b8whiGJ0pFyq9UUERdJCljvJB3Zt//XE8YiM
         83j6I7NURNUyF75bHtrMvvdLHPv9ybM1/C/9fNl7HLnEKeOj2U/AcOXaMIbsTCCbNlQB
         R4+wXmdaEA8BeobRFzPpeG/5aJJADv/b8ph3dJN+xLUGKgXRvVnX/XQ7Fav6ZlZGHoUv
         vpuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:references:cc:to:subject:from
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=amJSQlmqLp5nKpycLGZjEp6whnMPUFl4gdQ8NYO70zw=;
        fh=O6DBEjBP4v73cryNPChCbZvoqlgWfZ12v5fml1Kk+DY=;
        b=daHaJdVdbnmq+MzIjW2dvARGGuXS95xcAacqo0peOewRhBkZ3kAqlaYtKeMCA+ub7P
         ilk9eKaOaNR7REX0XGTj4gf972mo7NZhTnmxnhSU4zPQfe4MSDd3gg/03bzrLyTaFbDb
         tqkJnSkcjgPlW6faZxpI7C6IvK57fWNZGnzhXEfJ7aCbPv8s+0MxypBKkYpZFHb1RXdI
         4YT65J/t2GLLDsWCbFj1/vPOnzRD+6CV1/OZ+1xwxd+U9DQFdL3EvMEBeg928vUF1W/k
         /xqBMSMcVVqjf9P2bqJji0IyNVhN2G55XLc0SdPyU3mQDsQwIchcbp8Rj+LCu1PNn83I
         jcYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750848636; x=1751453436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=amJSQlmqLp5nKpycLGZjEp6whnMPUFl4gdQ8NYO70zw=;
        b=iBBuF+fFNPPtZ0qSH4cHe/ZcUZAzRNGfgm8c5AB7YrTPpM7SH5gZCg/m87eEQPxFl1
         asD1caXCiIWI7BOeacNV2LhoRxgGzXZRG+a/qcKqFoAqGcv5xr/CHEicobrdmyYvMxoh
         /ZqUK1fUgIsGy7y0CMMfxn1Ry3C2gMh04DUYvFC8vQ82mzgcj2bhIGX5WN9QcytAxYbt
         D8pxvwZeYZC7HJM9FoLNz++oWFPP0DHrP3Vvbvls/q6FP6uSTvuz2x3F4TVFI6KCcWHR
         AOI7Rbb5qvlP1tqYFnMgI5WjvhievfRG/njuzfjsV/Kqn21kp1fAxKSIuh6ULJBFZKRm
         qTjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750848636; x=1751453436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=amJSQlmqLp5nKpycLGZjEp6whnMPUFl4gdQ8NYO70zw=;
        b=iKIwZvbJ3/KKs/qcf5xlFoHBQY5DUu7EuVBijO2JbMUI8D0sE1EXf5+rQ+OZHiJtFV
         yR5ucUAapG7UJkpkeyfob8UdqijWiggu4d0tPwDRyfY8THtWtuXDqiXbGjwA9ziFjA+i
         KazSXMykAcJGe7tMSXW9I5+jhpNW043AZvmOqJ8syW1rPPVfswn+c3H1z9hAJoDYaksA
         ck4YHBxOyio/+/qvKX+85TBNlHED3R3AXkgXGfT5v6MrTL3uiq7MwMylwBpLfttnAKaO
         ptcGyBDCFUzaJFSrxzzjS+uCPOT/mj2gdoqjTjb/i57QnMOYNSPcCp6rONkMAHpjtwsG
         UkKw==
X-Forwarded-Encrypted: i=2; AJvYcCW/1XIh453Cgt8bPXUdCjt4kV+FVYlSYesFlohYxoG/EFohpmkZBSP5gFnbrp9RziSAnSeBBA==@lfdr.de
X-Gm-Message-State: AOJu0Yx+yyHNkdNiD9/TMYnZHuJApik2bWYKe2F07vreir8CkP6SQDuB
	Yx7HsUN4W6AwAC1u63AyzD6buXZQQsxl/nwul5N0XET2HnbQ+OzloCSo
X-Google-Smtp-Source: AGHT+IHsNA/KV4JvvqfBtIm/IetvQwtqodE1akFQpclUhiNClShtvcV+2qD2Gb38xxyP4VEuXUd3HA==
X-Received: by 2002:a05:600c:8b23:b0:441:d4e8:76cd with SMTP id 5b1f17b1804b1-45381af62f1mr22944115e9.29.1750848636022;
        Wed, 25 Jun 2025 03:50:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc5dIzIjgUVIi8UAh5mt7Z+GN5FNeiqSXdZG572/wVKhg==
Received: by 2002:a05:600c:1ca4:b0:43c:ed54:13bf with SMTP id
 5b1f17b1804b1-4535f27adfals33748545e9.2.-pod-prod-06-eu; Wed, 25 Jun 2025
 03:50:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyI2RYXw9RxgTRVDoMmcNz0/TCBVy6lmplG+WWaRmxjuE4ayF8/GUmtm1MsuUJPlbc3WHyZMGN7vc=@googlegroups.com
X-Received: by 2002:a05:600c:8218:b0:43c:f629:66f4 with SMTP id 5b1f17b1804b1-45383062895mr18157595e9.0.1750848633915;
        Wed, 25 Jun 2025 03:50:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750848633; cv=none;
        d=google.com; s=arc-20240605;
        b=RHozhcFf1ZwT8mAGQH0ssyHABoUmzRCMW6YjbtojZy/KhUxZ+EiT9D7IfZaX0QhRsj
         oJQ/JUMJDv/8YHmKOnnjqMVNXMuxe+inPjdxYWRV5u/JvgHWu6wkLz/2zVG5/oOvZY/Y
         Kmx8eHmgqGaEHltIejNiJ+oq7xQ0jmAhN9WU+9GGkeXnwq9+LYngfK3h3bmE/ZOUbW5/
         n0RfEQaGxJ/pwdQ/6XJPpEuwmGW/VDsGHZMXovOBMF6HgK5V7Zio325A6RI5kGtv38//
         NeNriGRYAGa0YY0AV+EHX16t4F2Gbu50BNts75rF06xSa6zfjc7x7KWvSFszvAskDyCH
         ORVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id;
        bh=GillNPWED+I7+g+LPn4LlQ45F2dOjncNPtfp8jyTpgU=;
        fh=SFdHZR8zxg6TEbE6MgAXQj1yZoKJ36rM9pB/hubh7sU=;
        b=iD+A+XGvRo+HUYHWrqHRnGPsTriupq0MXMMetUULmUED0t/IdltHiYRjLrFSa45970
         zBcNFaxTxl7ha6NtU5gEfoNojg/HqGpStZPKmQVdBP+9e0/STDUwfw7N4ruQ6LQNiGMs
         AQ4KHc9FWZ0VBYbjTh6vHUN3H/krm8r5D5bTF2sfiq3ox/zk1P337qSXwzy9EGEtJPZU
         /BLxQLWd+umFp4z15SLnx79JM7u5rE22WayQ3RYu0H/UCwnq4m/3gG/VGQ/3NIbAy6fN
         d1Tz6hG6hoJ9LDj+FV9+vM4tJ2wzDD83M8g3yKu6CvxQXA8cMNLg+UY6Ri0sBsJi8VG0
         6NZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTP id 5b1f17b1804b1-453814a5390si449575e9.1.2025.06.25.03.50.33
        for <kasan-dev@googlegroups.com>;
        Wed, 25 Jun 2025 03:50:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4bRyfz3MTKz9vBt;
	Wed, 25 Jun 2025 12:27:07 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id p2o-Y-FdKUAQ; Wed, 25 Jun 2025 12:27:07 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4bRyfz2RdKz9vBC;
	Wed, 25 Jun 2025 12:27:07 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 435058B7B7;
	Wed, 25 Jun 2025 12:27:07 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id vvosXbHhLt2e; Wed, 25 Jun 2025 12:27:07 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0BC418B7A7;
	Wed, 25 Jun 2025 12:27:04 +0200 (CEST)
Message-ID: <750b6617-7abf-4adc-b3e6-6194ff10c547@csgroup.eu>
Date: Wed, 25 Jun 2025 12:27:04 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 2/9] kasan: replace kasan_arch_is_ready with kasan_enabled
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, catalin.marinas@arm.com, will@kernel.org,
 chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
 mpe@ellerman.id.au, npiggin@gmail.com, hca@linux.ibm.com, gor@linux.ibm.com,
 agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com,
 richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
 dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
 hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
 akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org,
 tiwei.btw@antgroup.com, richard.weiyang@gmail.com, benjamin.berg@intel.com,
 kevin.brodsky@arm.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250625095224.118679-1-snovitoll@gmail.com>
 <20250625095224.118679-3-snovitoll@gmail.com>
Content-Language: fr-FR
In-Reply-To: <20250625095224.118679-3-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> Replace the existing kasan_arch_is_ready() calls with kasan_enabled().
> Drop checks where the caller is already under kasan_enabled() condition.

If I understand correctly, it means that KASAN won't work anymore=20
between patch 2 and 9, because until the arch calls kasan_init_generic()=20
kasan_enabled() will return false.

The transition should be smooth and your series should remain bisectable.

Or am I missing something ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
50b6617-7abf-4adc-b3e6-6194ff10c547%40csgroup.eu.
