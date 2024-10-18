Return-Path: <kasan-dev+bncBDLKPY4HVQKBBAV3ZK4AMGQEL5T7P3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 46C009A450A
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:40:20 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5c95ac2d13bsf1497830a12.2
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:40:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729273220; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mbqo3ykwyrw8EDlRwQExKbVFtivHCi4WFxEYPZ36VnN/NC+HLjiL/Ht/rpgTuz4V8q
         15VzpfBPGK8OcL5JPbqE9KytVVRCP7M/sT7ZLHwwPuaMu5aAofwT7S7Ukz+YwHLQYsPh
         2d8NCgdoE6szX/8fT9c66aFZ+oRE3ymwz/8KCZlO+xdRH7rXgtNljYQkMIE8UEoNpryE
         CjjmtbxLA92rHSJVSRfQ5PwR1oI4dYR420BBvMnNwMEjX14kUmy8gSF5a83UpIrKB0yC
         4VnQ/taOURhV7IztMIanOUd1/q/pFg3KDAaKOY9NgcWoFW+yjYgDDkzntb+02lueJrow
         9vXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=tO53YQWDRQd18nYFqWb8mnrD2vXic37+9SkZdeyZIUo=;
        fh=zjCrOeUIgs5I05AKEucV7Ry1qA752ugiYh8IE6Q0Lr0=;
        b=EgjPZG7xjcwqc5AmZ8WabRw+PZrhJpUN8AHDai9VrkZqLeFem2Z7z1ZU2mRxrkEdKS
         Bdac2HjQ6PMwoBiZd468fVcZc3Rbx9hiLCaHo1904DXUuygzX2bglG4xduqe0aMqTdFk
         rMy52xbKuiYPAmiGZyy6uYmyeH0WUGWpBxFMLkCwtJlLBHNNufFshUuWA1xJrJK6i3Ul
         kEanX7BNtVpdhrDxaFLPrn33b+YwcMwdIoV/xGMyr/jIYP1Y+i82EdxDmDeNVyFiNCnv
         XWfcabXTlX3tvzmkJf0Qx30GiRagjonIn+w8Pu8OBrC3WVOwFmQ1NlFB3PXmjun0aMFj
         cquw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729273220; x=1729878020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tO53YQWDRQd18nYFqWb8mnrD2vXic37+9SkZdeyZIUo=;
        b=Icr73ZyYYC5p+nKJhaiH54AUkqdRMdon9JGoECbPkrIuPqL2cpmE/furxq5pIUzrrz
         aQhoXaPMO7LXIf2vplmQzbwHxIaH+pYnWnSFIc8n4Cin2KWseZnB7+9YQSAA2OdKwVKg
         gGqKWBUxUl+LwP0yDiwEgrDrjdAMdy2XJAOIHcVYL/t1P96ISoxurHKsekARLCwEMKWi
         akstOk/HGAUCgVsv0RblW0mqPsRlhezRDJLA+ZPikc+WmE1teCFnt44jLBGzuDwJse6g
         a0a3lb7YrgOAVaAgwgpdWk4YXzQRl7n7UMH+sgPtlFAU9eHuAUAZvF5HVzlE5ZQgS/Ig
         aKcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729273220; x=1729878020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tO53YQWDRQd18nYFqWb8mnrD2vXic37+9SkZdeyZIUo=;
        b=uxSyluzbsoGh8ABwyUC+WR9t50Eo8a8OfDm+ySsGpIpby0Cr3GZ6tlJkLSOca4wdRO
         cSHi48meIS2eVIOUXx/f5mv278g+Di314sR9NjIJvjypPQIdlnS9ehYB72RNWauc0HEf
         W1ujKnsKpP+7Ae3pPQryMQz/vP/SrliG7zYfljqrjQyGvcdhWN7hHtbpQZDv6XZPzD2M
         UgxyM85gWFdUenai+9GTlwLasj/qqUWepW5fhSIMJmIPoa30kZaUoP6Cq8A+MJBYR7+m
         VB0/mGb0spt2atHAxfw9jNMGdqndtHJYFSvcivpKLTPvkdRWDbx2TyDA/aNWG8i9aETU
         GbXg==
X-Forwarded-Encrypted: i=2; AJvYcCU7Edy7xGiGGP8ANVY2GZjlKfnH+DlHrFL1xT2jhHIaWn45CPjE26ojkh42BF67Y2aM3lWVww==@lfdr.de
X-Gm-Message-State: AOJu0YyHZRXVIkbDS6QsekyqnruanUgz013YwC3LyKQ3SOIjO/LdMIDc
	keN/XUPPH+hgsxM6VjVQo2NHCPOAJXlFPTbB6Qon784a82AIoNtk
X-Google-Smtp-Source: AGHT+IHFfHYkobYL7O7b60oeeExX9QYUqbsDmXGoBlFHx0M86+rGTmjEeoKf7lBre0n784Sm3QxiLw==
X-Received: by 2002:a05:6402:26ce:b0:5c9:87a0:4fcc with SMTP id 4fb4d7f45d1cf-5ca0ac62747mr2353882a12.16.1729273219109;
        Fri, 18 Oct 2024 10:40:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3489:b0:5c4:6c19:f74f with SMTP id
 4fb4d7f45d1cf-5c9a5a31722ls1443568a12.2.-pod-prod-04-eu; Fri, 18 Oct 2024
 10:40:16 -0700 (PDT)
X-Received: by 2002:a17:907:720c:b0:a89:f5f6:395 with SMTP id a640c23a62f3a-a9a69a63837mr299962566b.1.1729273216314;
        Fri, 18 Oct 2024 10:40:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729273216; cv=none;
        d=google.com; s=arc-20240605;
        b=Pu5STDrgnjxM3yQI3yeWTSkitPKKolAnbBOO9tDfD9ld8YyN6VWC2psV7LsG2DmQJX
         IhoR75Efn2AG0gZmoPS4RTHsMjnI1843sxAPnpcsLYzLxQ9Id/jrgOZNu2aIuaF1oxEe
         o0G7T1FqBrxceoqilcNoloas/bkSAndr2VOekvHomLibl+Zzkos8R05jFfRFroaJ0dv8
         yYa78xaUqHEARJmoq7V1ArO2CuwGKlGZi0zX+VaGTOsqP8kxtntJUhWygDkDVhHNsmUr
         A5Aia+9D3zLugC1qknw32eJ3P+FOIjxoiUZd7P64Ize1WpzRs9G/1pmKLwygwU1DTXE6
         j4JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=v57rTYxRjrPWie/sbzb55q8HI0oXpri0RSDi3q5sTzg=;
        fh=waMq+E6muCHVDi9UmWJzPdhoSjMLRu8bOumcs+VT5c8=;
        b=Vtod5qStnTz6SlfDSRpNfyD0prW78VWmULUTCSXdDEjicQqxHQ2+idDOWWsGn9FJ17
         CIjLe0tFFE0p38wytlyL6X8aBz/8jkJV2qJizjrkB+rx3Oak9RMEogb5KxJ0TBa2Ie/k
         imEWYgeVS9riJJpnmT2d8ULLYB/k7cVOnx4L+FKdi2Ie2ADBJly2bK9iYz5tdnzLs9Qq
         Xc8RjwstUxnNJKfz4StJdsXSk5hm+7RuAp1QFuk+k3y5UH+a8qqBs5AWYRs1dnuYcNHn
         810wwzS0me87WAyXGd4PA9ZGYxeqM2nBfHqeIoBAkrWlfhmOuFm6GRF9gbn1GdUmeija
         0nGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9a68769627si3815766b.0.2024.10.18.10.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:40:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4XVX675pLBz9sPd;
	Fri, 18 Oct 2024 19:40:15 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id A60ALosMKCjZ; Fri, 18 Oct 2024 19:40:15 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4XVX674tplz9rvV;
	Fri, 18 Oct 2024 19:40:15 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 97B0A8B779;
	Fri, 18 Oct 2024 19:40:15 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ZaNkbIa7WNNO; Fri, 18 Oct 2024 19:40:15 +0200 (CEST)
Received: from [192.168.232.18] (unknown [192.168.232.18])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id CBDAC8B764;
	Fri, 18 Oct 2024 19:40:14 +0200 (CEST)
Message-ID: <0c81a6cc-2466-4932-805b-056d4e7dec2b@csgroup.eu>
Date: Fri, 18 Oct 2024 19:40:14 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 01/12] powerpc: mm/fault: Fix kfence page fault
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
References: <cover.1729271995.git.ritesh.list@gmail.com>
 <a411788081d50e3b136c6270471e35aba3dfafa3.1729271995.git.ritesh.list@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <a411788081d50e3b136c6270471e35aba3dfafa3.1729271995.git.ritesh.list@gmail.com>
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



Le 18/10/2024 =C3=A0 19:29, Ritesh Harjani (IBM) a =C3=A9crit=C2=A0:
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
> Fixes: 90cbac0e995d ("powerpc: Enable KFENCE for PPC32")
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>

Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>

Nit below.

> Reported-by: Disha Goel <disgoel@linux.ibm.com>
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
> ---
>   arch/powerpc/mm/fault.c | 11 +++++++++--
>   1 file changed, 9 insertions(+), 2 deletions(-)
>=20
> diff --git a/arch/powerpc/mm/fault.c b/arch/powerpc/mm/fault.c
> index 81c77ddce2e3..316f5162ffc4 100644
> --- a/arch/powerpc/mm/fault.c
> +++ b/arch/powerpc/mm/fault.c
> @@ -439,10 +439,17 @@ static int ___do_page_fault(struct pt_regs *regs, u=
nsigned long address,
>   	/*
>   	 * The kernel should never take an execute fault nor should it
>   	 * take a page fault to a kernel address or a page fault to a user
> -	 * address outside of dedicated places
> +	 * address outside of dedicated places.
> +	 *
> +	 * Rather than kfence directly reporting false negatives, search whethe=
r
> +	 * the NIP belongs to the fixup table for cases where fault could come
> +	 * from functions like copy_from_kernel_nofault().
>   	 */
>   	if (unlikely(!is_user && bad_kernel_fault(regs, error_code, address, i=
s_write))) {
> -		if (kfence_handle_page_fault(address, is_write, regs))
> +

Why do you need a blank line here ?

> +		if (is_kfence_address((void *)address) &&
> +		    !search_exception_tables(instruction_pointer(regs)) &&
> +		    kfence_handle_page_fault(address, is_write, regs))
>   			return 0;
>=20
>   		return SIGSEGV;
> --
> 2.46.0
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0c81a6cc-2466-4932-805b-056d4e7dec2b%40csgroup.eu.
