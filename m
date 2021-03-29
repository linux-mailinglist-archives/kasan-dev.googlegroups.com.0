Return-Path: <kasan-dev+bncBAABBTFYRCBQMGQEOF53C2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C30E834D70E
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:28:29 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id w31sf10814555pgl.22
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:28:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042508; cv=pass;
        d=google.com; s=arc-20160816;
        b=03Kp0WmowXCYa0ctZ7X+QCys6BPz6Rb4gM0ocy/huOlAoIzhsdgbkpMvk1YdvI9HWt
         HFgB+w/WbsfxNZz8roc8BAADAShGlagmv7GOXdUGFphuWduFUDdzVHHaF7iLNs150uv6
         FIDGf4TQ8rPfayI7pPM3udv77crF4OPoiLKxui8U99tYUgQXoY4KJyHnIgaj0chO/s7O
         VJuu9NZ2GYrwkwpzBiWjx1tSc8zHIyqGnt7QlAScboifOxfdXUkoGPJtafGDxdSR+OM2
         eXnndqoTyTgBNPZHZ/Gdt4Vc8ai+EqEafcdjuH/oZDxYuegb15yj2Kk1LhWfF3A1ZIVy
         jP4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=5equnqhv40gtOKM20maT0qCQO8Wr1BnsgGb3ma77jAk=;
        b=GcoLqYBsXDkAPU0vWevSRGevFD7ZXA8FSl8slUXvr2nrTzl1iJ3LJ1KfIZRjs07m8v
         rPjENRi2KBAy94MwqRD62ThBjZnLCx85QEaEqUt+c9haOGlA9nASnhjU9z1D8dB4Aw3P
         pEnSMh5jiAtlcGusrq0UUBGzxHHAt0YtUL/SuFBZlLVjMJi1RnwPtJyJxvdZ+0lQf59c
         KUE7w6/nyjzzxCaots9FCsZ1tbHzGp1F/DTs1DJcAqVkLbL22/PPJfNX0Ip1xZ2N13NG
         h/R2+bY221LwSQkNw1sYJ8rorkJ3Vzsqom+XvrU81TDuY3OeQx2rZ8xn6kcIhS8s6PQa
         Y2nA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=JRsHagF5;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5equnqhv40gtOKM20maT0qCQO8Wr1BnsgGb3ma77jAk=;
        b=NTQmCwPEa7+vUuj5jI1L5vDcqY73j/RCc2TuR3ClgzK2he7JwQ7hA7tilqKXNEpi+x
         164P37jjcmvkIvFruOngJKKkCEp+11R7O0nQV3GyvHJhkD1hnS/YFvpD2C8VaaTLQRXd
         muqboHPrUnMlpn3sH2+Q9JkpCcX3aImjO5IVPyG8NtBuoQqBsjhWbYukz/oqhrqTDq7N
         0aFqTY32UMa52HR6lYENtYltieNIypBGGsq8vS/rkLPOlV06TewnbWWu9ibCuCtGWlKV
         z5fR/aBTTgNrXpoTowrmdWHZ8lXjqm7TVfCeF7clw3EqKBjc2HTkur5/PhSAGpzNkFrN
         lRMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5equnqhv40gtOKM20maT0qCQO8Wr1BnsgGb3ma77jAk=;
        b=HkSTJeh6gAl7B3aN8qtgi+MUdctMPw1liwIlg/Vky72MuOl0iyqLf/NRQR6wRQMUaT
         kV6mhNy1qYYGeOYRIM6oYSJ0k6Q3i8NoSq4Jpkfa9NhA76w+UlHv+TfbyZYPazUrZDz2
         JB4CAU/8IAjsapjXrTtLSyCjzPXvkmKaZFojCx0vVCcwCtkXMEOxwxzlKTIuiT+yl/at
         3utxpZvlTzLfSwsYmoAeNbxU9Edpy5RP/Nf+naioBnvIJ7kPCk15sSagaoxr2DcsKEDo
         l9meuDlOQiWl/Ged+z4O+pUKkjJY9vKrB3fIhf7Z5mUiLAgZ+XE2YhPohIMV0NSunVcB
         CIuQ==
X-Gm-Message-State: AOAM533VSB14Fh3gwnv5HBN9QtVzwHMTTT1v/ZI7P6BWxLHR3qYCtOpt
	f+4LkSfAI5Ary5fCRrq3h5s=
X-Google-Smtp-Source: ABdhPJw1nNWxtL1oKDG6O/UlXA+Yc9w2MYB5fEpyWjyxDxsgXSFPRfe5s8i9mNBHer9bPxYQdQJ8bw==
X-Received: by 2002:a17:90a:c249:: with SMTP id d9mr455005pjx.104.1617042508110;
        Mon, 29 Mar 2021 11:28:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ce8f:: with SMTP id f15ls9392705plg.5.gmail; Mon, 29
 Mar 2021 11:28:27 -0700 (PDT)
X-Received: by 2002:a17:90a:c28a:: with SMTP id f10mr451384pjt.15.1617042507678;
        Mon, 29 Mar 2021 11:28:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042507; cv=none;
        d=google.com; s=arc-20160816;
        b=p1fkA27V7W2y2wJeGx2M9R2/DYyW34QKzleHdL1wVCs3dm6G2xG8KBezVSsQ2KO1Ms
         XR+QDfeeXt6ddLeVzPq+hMTJXYR73L4XH+bFCX7AWdzPH99brwFwED7lfnZCuOztM6mh
         1Vvm7sGFErR3UEfD7OnFVefFRLPFUJ8aeLu8jMZwlrp7ti+FWGgvjC00mHk4QBUXjnje
         rg4k/EVImbco7xQ9NfG5P+7+xn5yXGkGugn8TCguoefhs32gUr6I5x+E1L14hUpjx8C0
         XqetED0Exg/V9PqanVkBolWRoNbOOPWJ/oqUydKz5RRJ1kKJwHrNgUkBIF4k6uFMLEMO
         Zs+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ikp7PZAuK4fo1XgsXlr4Y+BaLjbJ/cSgtNEE/K8IQMY=;
        b=bAjuVknxsV6rc3F2Bn9Z9ZpoxAJzi+kK24Nqt4+49Z8iYxMgvFMXnyYvUqwem6PwFp
         J0xL4EY0O/FW9UtcAQLmbNYZ0ozEMpGvyvP99rtK9BFtfE85MZuVxPd81Ljs1RfzQCvC
         0k3wwtpS1IERjKPZAblVMAVC4JppX3O1+/kfzCeFqfio1MtvOnl4qvHimRwITENmc6/n
         0pWGmwIRfmDnEKxTzALUMvUrZ8E77cLiWs8ZoYtLkN4A/A66BILwQaQs9HyZifwsSBT+
         QIJ0oInIv41JvwGatEeoReomYa3uQhRwfEr6MQkwojw84CrQDNHX5xU/xkmgaZGxaGWN
         o1XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=JRsHagF5;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id a8si215927plp.2.2021.03.29.11.28.26
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:28:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygAnLkpEHGJgSvRpAA--.42329S2;
	Tue, 30 Mar 2021 02:28:20 +0800 (CST)
Date: Tue, 30 Mar 2021 02:23:24 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, "
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Luke Nelson
 <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH 3/9] riscv: Constify sys_call_table
Message-ID: <20210330022324.6737116c@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygAnLkpEHGJgSvRpAA--.42329S2
X-Coremail-Antispam: 1UD129KBjvJXoW7KFyxuF4kuF1rWw17ZFyrJFb_yoW8GrWxpr
	sxC34kKr95WF18CFyakFyxuryxJ3Z8W34agr1qkan8Cw13trZ8tws0ga4ayFyDGFZrWrW0
	gF4I9r90kr48XFDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkKb7Iv0xC_Zr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26r4UJVWxJr1l84ACjc
	xK6I8E87Iv6xkF7I0E14v26F4UJVW0owAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUAVWUtwAv7VC2z280aVAFwI0_Gr
	0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8Jr0_Cr1UMIIF0xvE42xK8VAvwI8IcIk0rVW8JVW3JwCI42IY6I8E87Iv67AKxVWUJVW8
	JwCI42IY6I8E87Iv6xkF7I0E14v26r4UJVWxJrUvcSsGvfC2KfnxnUUI43ZEXa7IU8Wmh7
	UUUUU==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=JRsHagF5;       spf=pass
 (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as
 permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
X-Original-From: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Reply-To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
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

From: Jisheng Zhang <jszhang@kernel.org>

Constify the sys_call_table so that it will be placed in the .rodata
section. This will cause attempts to modify the table to fail when
strict page permissions are in place.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/include/asm/syscall.h  | 2 +-
 arch/riscv/kernel/syscall_table.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/include/asm/syscall.h b/arch/riscv/include/asm/syscall.h
index 49350c8bd7b0..b933b1583c9f 100644
--- a/arch/riscv/include/asm/syscall.h
+++ b/arch/riscv/include/asm/syscall.h
@@ -15,7 +15,7 @@
 #include <linux/err.h>
 
 /* The array of function pointers for syscalls. */
-extern void *sys_call_table[];
+extern void * const sys_call_table[];
 
 /*
  * Only the low 32 bits of orig_r0 are meaningful, so we return int.
diff --git a/arch/riscv/kernel/syscall_table.c b/arch/riscv/kernel/syscall_table.c
index f1ead9df96ca..a63c667c27b3 100644
--- a/arch/riscv/kernel/syscall_table.c
+++ b/arch/riscv/kernel/syscall_table.c
@@ -13,7 +13,7 @@
 #undef __SYSCALL
 #define __SYSCALL(nr, call)	[nr] = (call),
 
-void *sys_call_table[__NR_syscalls] = {
+void * const sys_call_table[__NR_syscalls] = {
 	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
 #include <asm/unistd.h>
 };
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022324.6737116c%40xhacker.
