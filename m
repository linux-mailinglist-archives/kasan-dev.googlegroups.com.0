Return-Path: <kasan-dev+bncBC447XVYUEMRB6GQ56HAMGQEMWQVGXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C94D4892FB
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jan 2022 09:04:09 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id bh10-20020a05600c3d0a00b00347aa76728fsf3943643wmb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jan 2022 00:04:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641801849; cv=pass;
        d=google.com; s=arc-20160816;
        b=eVEQj3DPifAB1zS1sl+AePdK54BNQeHSsgqb0Cb7SZXhQXXUIJfZ/CSw3XyWPIDNIz
         Hp6qiQSOJ8tqgFB8OrgyCIbmTvpYX2EfrbjT0P3sGhxze1BOsWFtCXGIJa+p+YeXaXS1
         XZFrX+r1KVYS3AglDV53Qq96mJXRsSxt1Z0BnXeWQLruUDMK0am67w5cpUJo4q4EFwvD
         mNa3Ul6MQqQA2lfcFo8fxMpBVfuqcBYqPM4de3aKdlYW5s4ItF5dRYtFunabe0XzoWX7
         MoALcd9RPWryQ1lVGENWpt2fa4lHhQkNYqKbuUbpuA3FWKEIkg7r5kBDyPFIX17C63VC
         K00g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=VakICT+EigwI7k9nQZSlsRolI1+0J9lG/PnbYYut6/4=;
        b=DKDjxAOKfARVXFr00LNItX1UVILjTB9zl73vXH3Pf9MbAHEYfqOsbw3uDirLfml7Nw
         i6yzBpJEpOnhVgDPVB4MDxP/3al6ORK6XPiQRiPYh1b/mrj6A9yg75HS3RAwMnBPX5o+
         dw7fqEPXSKpKEXZs/RUWY6oiyQDYxejhTabJIa5y8JaAdupQp6NzscjNnKTsUwteQFAo
         5MQE6U2qMP1b4KWtKsDXGwTmyfncLdQfxvRE31zORTGFWcf7o8UCOpafhBELDqRll9Qd
         YI2lDriPB/lDdssEbf9fcm/YB/JZBrciVzJ+LWdxZC8wD0BJ9a/2VBGUTscp04jcT5zf
         UbNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 2001:4b98:dc4:8::221 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VakICT+EigwI7k9nQZSlsRolI1+0J9lG/PnbYYut6/4=;
        b=A/zXxYH02eqCkfWBseWU2QUYYe1rBKZWZDlBFJrP2x7RtEA2xuBKS7vU/xNJTaCLmv
         E4yqMEGypa7yy9nXg9aKzmJGYFbyIZiOVX6mM6IcQjlL6m7fY0+7oVUKuQkY3SlRHvY0
         +cLWsXFlEwsSMRFNi6xxvwQyIjQU6qla3ZOBeP37ObN5GRgBMmCGlEKaBycLzkXrutL0
         C4hfqLhuLcM0UO2VK6ZvIfRUkb6Y5L7LCrQaK7cqw8gWL1o5g7sORwUUTHSwiB/0R6FF
         4dyJXoH3Oc3Zzw41Gb/8QZr/ac314rPwhdnbp2ev3qXlffRaYJnV72UA4GVNToopg+NL
         Eabg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VakICT+EigwI7k9nQZSlsRolI1+0J9lG/PnbYYut6/4=;
        b=7lqNbYv+9vCqo8Qo6Yfux02lGA/T3XBMxEd5Hmg1xhK+Vrz7Z/VfpCkuoiWBodp8Ur
         jhkX0KdtBqypcYIWQ0CRXRB5rPT84UKctnMNN6gjUx1rB/hrSirKEbUa9+PbyR/58fVq
         LcJqoe+Xwp9rW1eDY+LBpxcFX6Aw8ra8LSqgV0hTUsqkXH6N4cf4eXbiV+SuzQKZtE95
         Jaje0Hb24l/iCgoygjR4T/8vEhg4HKc9qBMK/f4/QmRZgDVzHvBhMK/IS3hp9FV0InLj
         ARUXC7cK02unPS8vdNevqo3QFUOHW7M9nD3zSKxM1jGvJyc8jA1P/qRcnTLdpt6NPx/2
         RTtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336AFbp/7jhITHmidDVpgux/z7PNKBWt6TfZ7iYeSSFJNNVYmsZ
	3cc1b5OWbNSbTEGQu1tuP70=
X-Google-Smtp-Source: ABdhPJxWxklGGlxGetk/1nkI8pIy1dNnVAO7Lw556iK4HXPE08i9BBKXsiYyl+WZt77uNUYVVy4uAQ==
X-Received: by 2002:a05:600c:48a1:: with SMTP id j33mr1618005wmp.143.1641801848802;
        Mon, 10 Jan 2022 00:04:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls1372253wra.0.gmail; Mon, 10 Jan
 2022 00:04:08 -0800 (PST)
X-Received: by 2002:a5d:64c3:: with SMTP id f3mr62408069wri.295.1641801847959;
        Mon, 10 Jan 2022 00:04:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641801847; cv=none;
        d=google.com; s=arc-20160816;
        b=Igwn+alwJV74XcZODGkZ1Z0xoaJBbUTar+OIGh/JWMBcR+BnB6bly3MDBXOA9l86yc
         G/6fFa1Vs+3APspD+9bGzQI7NcIfCIs+F88+D7rbGmU+JPvesGqvOWdP7jGbi5cbs7W8
         JWTOw33ZNCfvqgQ4BRZLRJJb6Oi1im+15q7rjS1MBI3dXj/lMVPiTxg8mc2hSm6hlxTD
         vzANhWVnW7zX2PkRshjLl5VsZ1STR8Ns/vGTV4z0vfjOCkZkCM8LFVOmfNhepYTmnidh
         0yrJQ+FvXjlMCQEHVDDDDLGl/JIkqw/9RTBvcFI1vWj66pPBPudXoTW/d7rtJvSduyVp
         vTIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=sM5ekurIOOXJuD6rJTQvbP8qAqpaGXopY1o4kzODvks=;
        b=ETJVGMe58hsKnZjgMvevCWE/Wm+u2J65g0mMDHo0ta0ckBYYLQMD3/wnbtnTxeXaVs
         rspFp3q9OR53YZ9FLXNvzjLvvKUIp68iwjaUeXrKGRHW8IaueCtIZxsAI2NlTTn+c7uc
         K8wm7wd9j9ju5xeS20T8eRJ0RuhI8SI53v19ZJqjo40NgTEhwAvoPAFaJ40pCfZIAxPy
         mpUm9CQGnwNBJkUNH4poXprFkVR9LqLfAy3xI96cnrOcSwDaTr0SAsl0iCN6lX3x/3vx
         dytvGsrBa15Yc+XeESNy3vPKqLbV90xnSMofjytI2ldhSrLLwiafJtwrF0BrG2BMILOW
         05hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 2001:4b98:dc4:8::221 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [2001:4b98:dc4:8::221])
        by gmr-mx.google.com with ESMTPS id az10si42052wmb.1.2022.01.10.00.04.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 10 Jan 2022 00:04:07 -0800 (PST)
Received-SPF: neutral (google.com: 2001:4b98:dc4:8::221 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=2001:4b98:dc4:8::221;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 6A184240003;
	Mon, 10 Jan 2022 08:03:50 +0000 (UTC)
Message-ID: <44e6e00e-0b80-8329-bcc9-820940e02023@ghiti.fr>
Date: Mon, 10 Jan 2022 09:03:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.1
Subject: Re: [PATCH v3 12/13] riscv: Initialize thread pointer before calling
 C functions
Content-Language: en-US
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
 Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Zong Li <zong.li@sifive.com>, Anup Patel <anup@brainfault.org>,
 Atish Patra <Atish.Patra@rivosinc.com>, Christoph Hellwig <hch@lst.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>,
 Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
 Mayuresh Chitale <mchitale@ventanamicro.com>, panqinglin2020@iscas.ac.cn,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org, linux-arch@vger.kernel.org
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <20211206104657.433304-13-alexandre.ghiti@canonical.com>
From: Alexandre ghiti <alex@ghiti.fr>
In-Reply-To: <20211206104657.433304-13-alexandre.ghiti@canonical.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 2001:4b98:dc4:8::221 is neither permitted nor denied by best
 guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi Palmer,

I fell onto this issue again today, do you think you could take this 
patch in for-next? Because I assume it is too late now to take the sv48 
patchset: if not, I can respin it today or tomorrow.

Thanks,

Alex

On 12/6/21 11:46, Alexandre Ghiti wrote:
> Because of the stack canary feature that reads from the current task
> structure the stack canary value, the thread pointer register "tp" must
> be set before calling any C function from head.S: by chance, setup_vm
> and all the functions that it calls does not seem to be part of the
> functions where the canary check is done, but in the following commits,
> some functions will.
>
> Fixes: f2c9699f65557a31 ("riscv: Add STACKPROTECTOR supported")
> Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> ---
>   arch/riscv/kernel/head.S | 1 +
>   1 file changed, 1 insertion(+)
>
> diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
> index c3c0ed559770..86f7ee3d210d 100644
> --- a/arch/riscv/kernel/head.S
> +++ b/arch/riscv/kernel/head.S
> @@ -302,6 +302,7 @@ clear_bss_done:
>   	REG_S a0, (a2)
>   
>   	/* Initialize page tables and relocate to virtual addresses */
> +	la tp, init_task
>   	la sp, init_thread_union + THREAD_SIZE
>   	XIP_FIXUP_OFFSET sp
>   #ifdef CONFIG_BUILTIN_DTB

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44e6e00e-0b80-8329-bcc9-820940e02023%40ghiti.fr.
