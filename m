Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBPOMXC4AMGQE4QWXSQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1183499E0E7
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 10:22:24 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-71e7858820esf451678b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 01:22:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728980542; cv=pass;
        d=google.com; s=arc-20240605;
        b=lTHZtxUTLFp6kLBjGkanfKpr6EQ6cKErvJ/tgWzieK2sJhT+saK4SIxY5FV25fYwPY
         JUMYWPRA6UTsoQESA9G/T8epFMcYz+6wnsLuYNenbznDKEhmkO2XrU08g7ZaHxGrV5FQ
         OIzfCTHILGhSXK9xXuxGXHLmSeHyIjZ8frfKHTkEnrryJ/FErzaXWnedkMx1Lh4Qj3EM
         i+yH3/segAynveeANqLvIFI3eYkW3ycHPqpSL3y1fiI1K6SuDlUOCDD9KlSmbmjZvbjB
         QJtdfQiS//qJiREWOP5QyuVyRmpWM1zZZPM5MPTjki/w7txzEXoxxR3rKRZWskrTsiOU
         XbuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:message-id:date:in-reply-to:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=p/n35yLf6NK4hICiPjNqfcWoZmeOsSh5wkFdgqDyJrQ=;
        fh=/M0JgarQf6PxBznJYysKliXHngDh0Krvo5y4YANci4U=;
        b=bOuPA/MjwLLwUvEqwtsMdd988G8j5ibZlTZet/GscePVbevNDeRzC2o/BUW/fcR4xN
         s4Up4osj6duCm9IrXCnPUxkn3HoKsfOAHbqBsiSGvkAw2qcNSbMTyH7FjEkTnNyAiB9T
         fN4mBQWQrV964eLFnPk7W5xB557yUgcd0Q8OSPDvHXsXwFrwR7q2wyUwV7cQz/sleAhD
         h0h7y+GDYHOIawEoTuAMMd/KgjdJEOcP5C+2p3a4IdhS/4MzCwftEEl2fmJ6YBFsiuz+
         m1Ab0AFCiBqq7ILCs+gPjkZ5wpP4RuIl5w2A3kL+wpIHUZbuPK3NHj1pn3FT8scvzAL9
         la8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AwOLqw23;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728980542; x=1729585342; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :message-id:date:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p/n35yLf6NK4hICiPjNqfcWoZmeOsSh5wkFdgqDyJrQ=;
        b=o3tDUERdANPNrcP9kKlS+Bw9DwYhI2rSKr/2Nw4Rs/bPL7W9+JZ2JRwQ5FcRXnuou9
         s/AmacIIWXGCGJRDibEdvKJkGWvn8+/xOIOFVetcaE81LMphBvAj40wfdDIfMuBpo31f
         UV+5nx1IUM4+IBEHu6UjXCyXFLLLdNqTtGXqflJuYMM23UO0vfmT6yb9HxtaCwguNuD1
         8GrhH3cSR7yFjtj+bS6vkDRq+c8rPNR0pVHd6C8dL90nveGZb5JTS9mZkYz1DoAdlrKH
         NBrMGQ0aiRYptvM2MawgIdd/K4YmvNuumIQLlNxyCuNwhpqwjxkSfHdI/CpJptwYHECI
         rsAA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728980542; x=1729585342; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :message-id:date:in-reply-to:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=p/n35yLf6NK4hICiPjNqfcWoZmeOsSh5wkFdgqDyJrQ=;
        b=nbMeUKWxbHsk17uX/tQ9D2J+MjBzPo+eSArOo76lp9SsRQQaE1kNASWtb+bW/iw4d4
         XpcIuEZG12RNTbdc8kZoDXL0M/YaX0VeYwQmoY88Kr1h6w6Dyu+EqyfApv1mmCoax79E
         9SNZfjOy8Lf9r5IzY4bRFOeLuS64fS5ExLsuFA/LJkMNbCzJcIIUzNVBiPb9ShPL5pfb
         iPDotcsTTWOIGT9QrblBzzNoSRclAaOuPvvW7ibF8ZbFGcjR2Ymw50dP0Rpfkhzfm9QA
         QRVBlPbws/IidN0Fox8zDA4bOMO8pVXccSh8x5va/5JgrlPjSCRGo1rFEwKDoKY9RGSv
         WNAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728980542; x=1729585342;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p/n35yLf6NK4hICiPjNqfcWoZmeOsSh5wkFdgqDyJrQ=;
        b=dY5Feaf2ESvR9xhgGurDYPRXlY64NIALAGU6W0Y9DMCv7ogOB1jliIXEHM9lZ8rZoO
         F8spnrGiyHrJ4vXWGdC9VnTirYtdEOSTe/2hSBgRbVcJgcqQre2M9tJLX84Mq7ohu2W1
         91lvvYT48VP3KChuAXDvsDxiTNBOf43yt3UeJUsylytwGBEfxDmi2v7oJY0xhKXVOfgl
         HpT4UzwxhdKxyjOWVHwcSRhCdhTZMtQz5xSR4DmWsJxKXcz1/dgwxaQhzLJHVFdiaCiw
         2/5Gmu3QtI55wi/a5BBcsJygZ9dVOOBG0EhlnM4bTacWl7cBptgIGKi6QajscO22gO4/
         lGWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkUUgZDVTMqE+xesRTnOgEQremgfDvgYovK9kSMnaYuw+dPb35HJ0ZMGVd+w8g7+Wg0LadBw==@lfdr.de
X-Gm-Message-State: AOJu0Ywa/vUg6rF5FsCUNUH6d5epzvI+0GTK2SYt9UjpBddDt9rUY09t
	4VzJQLLBCY0ETaCwjv0zSrAj5LqyTcA8ADuyreA7qekO22THrNlB
X-Google-Smtp-Source: AGHT+IGMKTtXvi+mqPR/17C4LyGsk3CDBTyWOWaiyJxSYaFbHHGLNE/mX1DgTT9jmEaiJTgpN2+7nw==
X-Received: by 2002:a05:6a21:150a:b0:1d2:ba7c:c6e7 with SMTP id adf61e73a8af0-1d8bcf5abaamr16757401637.30.1728980541694;
        Tue, 15 Oct 2024 01:22:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3fc6:b0:2e1:854b:d41a with SMTP id
 98e67ed59e1d1-2e2c833e7fdls3369940a91.1.-pod-prod-03-us; Tue, 15 Oct 2024
 01:22:20 -0700 (PDT)
X-Received: by 2002:a17:90a:ee85:b0:2e2:e8fc:e0dd with SMTP id 98e67ed59e1d1-2e2f0dc33f8mr15633272a91.35.1728980540125;
        Tue, 15 Oct 2024 01:22:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728980540; cv=none;
        d=google.com; s=arc-20240605;
        b=CRdKF8bWgJEFMrqlO/a3wMwv5SGZrNT2Kvgt9DIo7V9d0o+NvrmgtqmW4Sa2gMgeF5
         lXN3VNABEdzXOD1MhimPoiaUe6ZzTIeDAB2l+zik4ieVDBURM+Rpc0Op5Oike1vZJIWF
         YwCZ0xlbXya0nQ2FDzerGbzbyhNRgoVpqO/1r9LmnYA6O5593lWIVkpcYNDjTjcI3vwl
         hGKbZsZdS4l4lTugqjBlqc7gHOFM1zGBVRiMN7j/AfbR9w+PSkzFHbT7qPVQKAsbu+vf
         O977JZqle8LGk5HOkGxLljFH16Fln+8aZoBP2FNtucF6lbKDKec5zZciovH3Av3C18SX
         sQsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=gSbjcDDQQ4bzhuGeYvy25HeVmQJUWahcI9kmdF2A54o=;
        fh=0hmm18NE8zr3I3enYzpOBWtqHj/oVkl/n+j6e35drWI=;
        b=kR6EtYcuQ/lDmw7ncnAlzP4mOZqzWRffANqLtne6ww77j7E3X7+eM+hNXmRr4vmqZh
         YGbxa3GVno1EF3JwoSzJUleuhL+xsR6Tj+yiIiX/OwtBsgDeVJxjPeAD5+YooQs7dC2p
         nRcQPscqZ/d4eYEWM+xzIs7QXAgzmZ73+dmo8vsydpiz9QLkBaiVfD35yvnF+XUsP0FM
         nT9eS/Y8ojUckhisqtgEGUPaMFMif4TOhBMSya4WSIavQOlQ9CCzou5YDciTUJujKguc
         3lp+t6+MjmhreQWrF+wDSZAWf7HzVUyGzMBVtMLcUEFgK2Y9ewJHU+NnH/YCAky76yLO
         C7gQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AwOLqw23;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e37f1cfcc2si190047a91.0.2024.10.15.01.22.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Oct 2024 01:22:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-20cdda5cfb6so19654535ad.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 01:22:20 -0700 (PDT)
X-Received: by 2002:a17:902:e5ca:b0:20c:805a:524 with SMTP id d9443c01a7336-20ca16be1b7mr170171755ad.39.1728980539523;
        Tue, 15 Oct 2024 01:22:19 -0700 (PDT)
Received: from dw-tp ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-20d17fa48b9sm7087565ad.85.2024.10.15.01.22.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Oct 2024 01:22:18 -0700 (PDT)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Heiko Carstens <hca@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>, Hari Bathini <hbathini@linux.ibm.com>, "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>, Donet Tom <donettom@linux.vnet.ibm.com>, Pavithra Prakash <pavrampu@linux.vnet.ibm.com>, LKML <linux-kernel@vger.kernel.org>, Disha Goel <disgoel@linux.ibm.com>
Subject: Re: [RFC RESEND v2 02/13] powerpc: mm: Fix kfence page fault reporting
In-Reply-To: <660a2cf7-24f9-4558-87df-5e4c13362380@csgroup.eu>
Date: Tue, 15 Oct 2024 13:49:46 +0530
Message-ID: <877ca9zskd.fsf@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com> <6bf523aa03e72d701d24aca49b51864331eed2d5.1728954719.git.ritesh.list@gmail.com> <660a2cf7-24f9-4558-87df-5e4c13362380@csgroup.eu>
MIME-version: 1.0
Content-type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AwOLqw23;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:

> Le 15/10/2024 =C3=A0 03:33, Ritesh Harjani (IBM) a =C3=A9crit=C2=A0:
>> copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
>> /proc/kcore can have some unmapped kfence objects which when read via
>> copy_from_kernel_nofault() can cause page faults. Since *_nofault()
>> functions define their own fixup table for handling fault, use that
>> instead of asking kfence to handle such faults.
>>=20
>> Hence we search the exception tables for the nip which generated the
>> fault. If there is an entry then we let the fixup table handler handle t=
he
>> page fault by returning an error from within ___do_page_fault().
>>=20
>> This can be easily triggered if someone tries to do dd from /proc/kcore.
>> dd if=3D/proc/kcore of=3D/dev/null bs=3D1M
>>=20
>> <some example false negatives>
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>> BUG: KFENCE: invalid read in copy_from_kernel_nofault+0xb0/0x1c8
>> Invalid read at 0x000000004f749d2e:
>>   copy_from_kernel_nofault+0xb0/0x1c8
>>   0xc0000000057f7950
>>   read_kcore_iter+0x41c/0x9ac
>>   proc_reg_read_iter+0xe4/0x16c
>>   vfs_read+0x2e4/0x3b0
>>   ksys_read+0x88/0x154
>>   system_call_exception+0x124/0x340
>>   system_call_common+0x160/0x2c4
>>=20
>> BUG: KFENCE: use-after-free read in copy_from_kernel_nofault+0xb0/0x1c8
>> Use-after-free read at 0x000000008fbb08ad (in kfence-#0):
>>   copy_from_kernel_nofault+0xb0/0x1c8
>>   0xc0000000057f7950
>>   read_kcore_iter+0x41c/0x9ac
>>   proc_reg_read_iter+0xe4/0x16c
>>   vfs_read+0x2e4/0x3b0
>>   ksys_read+0x88/0x154
>>   system_call_exception+0x124/0x340
>>   system_call_common+0x160/0x2c4
>>=20
>> Guessing the fix should go back to when we first got kfence on PPC32.
>>=20
>> Fixes: 90cbac0e995d ("powerpc: Enable KFENCE for PPC32")
>> Reported-by: Disha Goel <disgoel@linux.ibm.com>
>> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
>> ---
>>   arch/powerpc/mm/fault.c | 10 +++++++++-
>>   1 file changed, 9 insertions(+), 1 deletion(-)
>>=20
>> diff --git a/arch/powerpc/mm/fault.c b/arch/powerpc/mm/fault.c
>> index 81c77ddce2e3..fa825198f29f 100644
>> --- a/arch/powerpc/mm/fault.c
>> +++ b/arch/powerpc/mm/fault.c
>> @@ -439,9 +439,17 @@ static int ___do_page_fault(struct pt_regs *regs, u=
nsigned long address,
>>   	/*
>>   	 * The kernel should never take an execute fault nor should it
>>   	 * take a page fault to a kernel address or a page fault to a user
>> -	 * address outside of dedicated places
>> +	 * address outside of dedicated places.
>> +	 *
>> +	 * Rather than kfence reporting false negatives, let the fixup table
>> +	 * handler handle the page fault by returning SIGSEGV, if the fault
>> +	 * has come from functions like copy_from_kernel_nofault().
>>   	 */
>>   	if (unlikely(!is_user && bad_kernel_fault(regs, error_code, address, =
is_write))) {
>> +
>> +		if (search_exception_tables(instruction_pointer(regs)))
>> +			return SIGSEGV;
>
> This is a heavy operation. It should at least be done only when KFENCE=20
> is built-in.
>
> kfence_handle_page_fault() bails out immediately when=20
> is_kfence_address() returns false, and is_kfence_address() returns=20
> always false when KFENCE is not built-in.
>
> So you could check that before calling the heavy weight=20
> search_exception_tables().
>
> 		if (is_kfence_address(address) &&
> 		    !search_exception_tables(instruction_pointer(regs)) &&
> 		    kfence_handle_page_fault(address, is_write, regs))
> 			return 0;
>

Yes, thanks for the input. I agree with above. I will take that in v3.
I will wait for sometime for any review comments on other patches before
spinning a v3, though.

>
>
>  > +			return SIGSEGV;
>
>> +
>>   		if (kfence_handle_page_fault(address, is_write, regs))
>>   			return 0;
>>  =20

-ritesh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/877ca9zskd.fsf%40gmail.com.
