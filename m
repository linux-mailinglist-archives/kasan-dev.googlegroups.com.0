Return-Path: <kasan-dev+bncBDLKPY4HVQKBBYE5XC4AMGQE54C6W7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D4B8599DE9C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 08:42:42 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-539e4b7c8f4sf2824290e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 23:42:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728974562; cv=pass;
        d=google.com; s=arc-20240605;
        b=kwEJSpp59kXoCmM2VAuGswXVTrw5c3E/osnPohAppL4oh6c9fOTsaGXtLLJWmUXhpf
         ggglk8cfi0kzKUaz3UiQm+Jj9aRMyqmTvGffBJmOp6of0sAk2OcVZIGOMqTsUcfJ93WR
         kRpDsPyo+8Jjch7EqtH7uT53iJyhXXG0AealYB0MvE5smhcmu45zccnLrZBQLBkowx+V
         QZOi+olPETnG13NFklMmEg9j3j81xNZDtU8/EVFGIqyAErau9TUKD4yXB0WpAg9qG5kL
         tcW2ow00c6qrMHW2ZBzf6GbqqEnQIyQNbYhFdmWBcQKrzn1YwJdG6vc20p9y7qVqFL3o
         L4jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=ttUAUlmUq1QsJmtM6iEZ+gMC0IZMQeFs/pr9VB4uIK0=;
        fh=6xA6CQEdHFUwwjF4Pa4E3ibYA2bEn6EIwWxKxvCpIys=;
        b=gefiO54ImoHNqjH/PrfcxUz5D6Z/8RzZwY54k7Kn2B4fuK0fbR8lzpFwVGCEeiWkhW
         FiFUNew7/q/MqM/OtH5qpPax8vikFHGWX2gDwe30cbrzR6PiMd+kouQcGC5XsnFZJ3OL
         2Gs24VkuDZHQfLpCrjqW/2yugUumdjRLFQ6zwyAkkdrramZl5A/z0UGOPhOWaW64nY8D
         +U/0xYQX6Z8i7oTt1/vOEuSG8YUV8eUTUlxL0XVqp4hGN8sNQ5+uZeM7CbGhtAdspR6y
         mAnMfIVTcEgGidytcitGdMwUYgtKGo6rN+YTBhdbK7637a0QJeXhWuyNeKhGwKMWQLtG
         XEuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728974561; x=1729579361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ttUAUlmUq1QsJmtM6iEZ+gMC0IZMQeFs/pr9VB4uIK0=;
        b=PKsPZG+gBr3hhTQ9yPuS1pqTt+D7V6fjfNc9sfvO5SQZUdbwJ0olijy1wO4WgoCpkN
         0Jmj8GBN2FcRlElXXtnTlnh00/jsIz8eJad0SaRYUlVlHVXndtW9VzSCW63XsZBB6fZe
         FsWgBju34BAKvywRrGDtLDpVrd8V0c4mXUwcjJPjhdWvbVa43toesB7ZQsiLSJmygLr5
         H2PWF4Tg7stdMlBh/uWlOSbYu9yWxbjhxmBLkb1bEJM+V8HUqzhm+znh6zGTjUKFLUWx
         sr20Oraj0FGXZIZSxoUUNv+8bfC2QZnB6LTs6moI1V3gR9HoMUwXrApRe/g72KeWriau
         3u+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728974561; x=1729579361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ttUAUlmUq1QsJmtM6iEZ+gMC0IZMQeFs/pr9VB4uIK0=;
        b=X/CsKMS9n8T1WCN0YCHFzfU9Qbqv8jMtFhwLq4PUNixoND5LBV+z9epvPBDCUY1pEn
         /d8RXtT7UhprA6MPx5LJV3zNo14Mri/Awiaibh68bYPWWcAsjDCSdvfaF9qI9/G0iUij
         tywfh3VQjmcGF5TQYxMhCkOzcuPpg9a8Dc2g48HLv+PDobWfTwvLT2vD6mfu8LkTkKpj
         /PFHOJyTigIfXx6xPfx9Cjl0WLxMiHmdtW+LM9wDJ6RQwi+ccUEWUPwXkYuUTXCUlrwU
         OVwOla8UhAiDoC7FSQ7eTPLPssZSLwq8y6FEc1ZXbmRy1rTHikSDdR2hGl7pMJl0W6bm
         UHlA==
X-Forwarded-Encrypted: i=2; AJvYcCX2FbfJcAIeOYiKyVVDG6slJ7OS1j7vKp2lAxz1t86qZcL232TBDdhszWBw8av2TbGhN18YUQ==@lfdr.de
X-Gm-Message-State: AOJu0YxBvfCNkr6TpJBB/fxWABbaqQk1Sxypo2MycCl07MJpICnVAtro
	p1+oZtmDsDK4Rh54KoX/O+PDe8n8yfsna1wyfOrWoxEXrlpLugQM
X-Google-Smtp-Source: AGHT+IEWQSCjeYdTlg3OgR+CafK2/ixG+IhTA65UUcVeqyup5E9Vw/QkFx5qPUoNjLENw4uBkN4Ekw==
X-Received: by 2002:a05:6512:3b90:b0:539:fcb7:8d53 with SMTP id 2adb3069b0e04-539fcb78de2mr1807722e87.46.1728974560829;
        Mon, 14 Oct 2024 23:42:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:512a:b0:42f:75e0:781e with SMTP id
 5b1f17b1804b1-43115fdb7bfls20342005e9.1.-pod-prod-09-eu; Mon, 14 Oct 2024
 23:42:39 -0700 (PDT)
X-Received: by 2002:a05:600c:45ce:b0:42e:93eb:ca26 with SMTP id 5b1f17b1804b1-4311ded374cmr117736255e9.11.1728974558952;
        Mon, 14 Oct 2024 23:42:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728974558; cv=none;
        d=google.com; s=arc-20240605;
        b=FuLis2v8mGjGpcmDAQ6ZkS/KfVx3stzZIILGZYcmASJ4NppNOTCula9eQWLofN2N8s
         SJiLF0qNuz97kXpTI/1g71arPoHRvAdOSL1nANtuJdSWEi9Q7+v1HhMXmOsCxlWdY5eg
         q4gkzGnm5Hco8XHvM0cAbwFGLlvxoLnYQhs4zHW3GVmhK5ZNXJUEDYUvtW7ftxMr0Qdj
         QV2K/krOvVWq/eUW3oFCCn/nkkxvdeX46153rcWsnbiBufrf2uwsxZO6BiKt3qfBWpjv
         G7+ZbghBnCsM0D25T2k5DC6HLUZ5uArcPUcqVCb+U+L+hs93G0sQhc15Q6T3YH3e5rO1
         YLDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=yZY8Q+WVwnCzpj20CVghuUX3o6Hwo32dGoF20noZK+8=;
        fh=waMq+E6muCHVDi9UmWJzPdhoSjMLRu8bOumcs+VT5c8=;
        b=RPJ2EJ7K0NKb8ZIApqU2YhEq29orO1Bt38dACTDlO8woMARkYDT0ncNQwHLymND0A0
         4nbt+IQ1USInr2+s063lWjrLBDs1pAORxR5R2ruig0momCRT0oGkVRZmCyYoxZ5RKngj
         Z5sA4mN9aEq5jMbk2qNlKMPaY5njz/V0PUOPY61f5sAuLKR5ws+Lt4dNIR6TRWSrLWx6
         7KEFyoowT5jT6mOuz5i3RHDxW4tfkgu3CLSt9AFXD2r8GF0UzSTBG5g46a+PtYJi0NEa
         GvwRVlQxZLTtYpBeuZhiGFdYrz44ibqbV4COevTEhzUTXmAwWHAS7lf/tDCgorYOnQqm
         CoZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43055b3f3bdsi7967255e9.0.2024.10.14.23.42.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 23:42:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4XSPfk3bvFz9sPd;
	Tue, 15 Oct 2024 08:42:38 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id jWUMtT-TFO-Y; Tue, 15 Oct 2024 08:42:38 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4XSPfk2bjlz9rvV;
	Tue, 15 Oct 2024 08:42:38 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 456068B766;
	Tue, 15 Oct 2024 08:42:38 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id haU307l0a_y8; Tue, 15 Oct 2024 08:42:38 +0200 (CEST)
Received: from [192.168.233.13] (unknown [192.168.233.13])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6D1568B764;
	Tue, 15 Oct 2024 08:42:37 +0200 (CEST)
Message-ID: <660a2cf7-24f9-4558-87df-5e4c13362380@csgroup.eu>
Date: Tue, 15 Oct 2024 08:42:36 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC RESEND v2 02/13] powerpc: mm: Fix kfence page fault
 reporting
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
 linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Heiko Carstens <hca@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>,
 Nicholas Piggin <npiggin@gmail.com>,
 Madhavan Srinivasan <maddy@linux.ibm.com>,
 Hari Bathini <hbathini@linux.ibm.com>,
 "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
 Donet Tom <donettom@linux.vnet.ibm.com>,
 Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
 LKML <linux-kernel@vger.kernel.org>, Disha Goel <disgoel@linux.ibm.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
 <6bf523aa03e72d701d24aca49b51864331eed2d5.1728954719.git.ritesh.list@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <6bf523aa03e72d701d24aca49b51864331eed2d5.1728954719.git.ritesh.list@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
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



Le 15/10/2024 =C3=A0 03:33, Ritesh Harjani (IBM) a =C3=A9crit=C2=A0:
> copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
> /proc/kcore can have some unmapped kfence objects which when read via
> copy_from_kernel_nofault() can cause page faults. Since *_nofault()
> functions define their own fixup table for handling fault, use that
> instead of asking kfence to handle such faults.
>=20
> Hence we search the exception tables for the nip which generated the
> fault. If there is an entry then we let the fixup table handler handle th=
e
> page fault by returning an error from within ___do_page_fault().
>=20
> This can be easily triggered if someone tries to do dd from /proc/kcore.
> dd if=3D/proc/kcore of=3D/dev/null bs=3D1M
>=20
> <some example false negatives>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
> BUG: KFENCE: invalid read in copy_from_kernel_nofault+0xb0/0x1c8
> Invalid read at 0x000000004f749d2e:
>   copy_from_kernel_nofault+0xb0/0x1c8
>   0xc0000000057f7950
>   read_kcore_iter+0x41c/0x9ac
>   proc_reg_read_iter+0xe4/0x16c
>   vfs_read+0x2e4/0x3b0
>   ksys_read+0x88/0x154
>   system_call_exception+0x124/0x340
>   system_call_common+0x160/0x2c4
>=20
> BUG: KFENCE: use-after-free read in copy_from_kernel_nofault+0xb0/0x1c8
> Use-after-free read at 0x000000008fbb08ad (in kfence-#0):
>   copy_from_kernel_nofault+0xb0/0x1c8
>   0xc0000000057f7950
>   read_kcore_iter+0x41c/0x9ac
>   proc_reg_read_iter+0xe4/0x16c
>   vfs_read+0x2e4/0x3b0
>   ksys_read+0x88/0x154
>   system_call_exception+0x124/0x340
>   system_call_common+0x160/0x2c4
>=20
> Guessing the fix should go back to when we first got kfence on PPC32.
>=20
> Fixes: 90cbac0e995d ("powerpc: Enable KFENCE for PPC32")
> Reported-by: Disha Goel <disgoel@linux.ibm.com>
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
> ---
>   arch/powerpc/mm/fault.c | 10 +++++++++-
>   1 file changed, 9 insertions(+), 1 deletion(-)
>=20
> diff --git a/arch/powerpc/mm/fault.c b/arch/powerpc/mm/fault.c
> index 81c77ddce2e3..fa825198f29f 100644
> --- a/arch/powerpc/mm/fault.c
> +++ b/arch/powerpc/mm/fault.c
> @@ -439,9 +439,17 @@ static int ___do_page_fault(struct pt_regs *regs, un=
signed long address,
>   	/*
>   	 * The kernel should never take an execute fault nor should it
>   	 * take a page fault to a kernel address or a page fault to a user
> -	 * address outside of dedicated places
> +	 * address outside of dedicated places.
> +	 *
> +	 * Rather than kfence reporting false negatives, let the fixup table
> +	 * handler handle the page fault by returning SIGSEGV, if the fault
> +	 * has come from functions like copy_from_kernel_nofault().
>   	 */
>   	if (unlikely(!is_user && bad_kernel_fault(regs, error_code, address, i=
s_write))) {
> +
> +		if (search_exception_tables(instruction_pointer(regs)))
> +			return SIGSEGV;

This is a heavy operation. It should at least be done only when KFENCE=20
is built-in.

kfence_handle_page_fault() bails out immediately when=20
is_kfence_address() returns false, and is_kfence_address() returns=20
always false when KFENCE is not built-in.

So you could check that before calling the heavy weight=20
search_exception_tables().

		if (is_kfence_address(address) &&
		    !search_exception_tables(instruction_pointer(regs)) &&
		    kfence_handle_page_fault(address, is_write, regs))
			return 0;



 > +			return SIGSEGV;

> +
>   		if (kfence_handle_page_fault(address, is_write, regs))
>   			return 0;
>  =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/660a2cf7-24f9-4558-87df-5e4c13362380%40csgroup.eu.
