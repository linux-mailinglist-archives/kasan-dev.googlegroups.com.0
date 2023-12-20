Return-Path: <kasan-dev+bncBDW2JDUY5AORBSO7RWWAMGQE3BSD4KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7608E81A97C
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 23:50:51 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4276353f93esf21509541cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 14:50:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703112650; cv=pass;
        d=google.com; s=arc-20160816;
        b=tFsu2cLn8YiJ3xzdSb50Hu2EUn4cvCouOGhCev6FClOhot/REpbexCkVUxviP0KEp4
         ihIAjtMTLMKsG/NkN2OrMimp4w8NXJAtJhghVRge7OUvFwp/vros9cmrj0m3TbQkkh00
         +seXd63JqLfn1GtAhDN1ZglWkK3AMtze2eHp72l+DhI8XWO/yQAqFX+kyNyb9v7NwCO/
         DleFYuC+TcdNW7in3NqdMTp6AhTn6yxcAa6ZIZc/AU+1TQcZOkTHOylHRlZjQmYB/qTe
         eoJU3JWmFaH8A6eKkbM59P4ZjtrWWyg9c6jXK1ypVdItS0cTM1BYNViv0Kg45qf7iXGa
         V9dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=HkuI0atpU9ui9BcXsHGFnzK7SNzuubvibu6xb00ZgWQ=;
        fh=49O59YDaPrqO8qZGRPL9x8BJHS/UXHHGBJd7UgkdYDk=;
        b=B4MZgjflOW9djRYDvtCdAT+w12jY2VepXRKH6EoOgvk5ihyE48PTx/bbR2KOX3bStu
         74Zxc26aTmncWHFpL71cJEnRpEwV7hdTScApGj4fpNWvQ1FXbYWFncRejX7bdC8Mo5eV
         ZJnqzXBXQm5tiZ8BJmNhxT/J89EDjTHAdWKJg0gfTOu23Gw8eXcodynekfEqmvcugKsR
         8pp0zs0YJm++Xo15enLKCpS466OXjF9V7kZtmTcC0uOdKAEhaRkGd5DwDWma2uU+csW8
         wwS+/M8rnp+R1UylcZ3mX5sGfDT+45ob1dsSh2T7Xr5fBaN4Jsq3X3Qe3qgV/s6wRiYU
         /+0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dVmXacB0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703112650; x=1703717450; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HkuI0atpU9ui9BcXsHGFnzK7SNzuubvibu6xb00ZgWQ=;
        b=LR0idwy2LRR+/j2zwoLE/JmTLu08xDAF39I1pGfW2KFGDUFGVEZOmQq35pYC9Slh2x
         p8pss0lSdrvtnI6MXrdjo5qujtdp7NAnk1SeuFkZsn4cEspzOwD+OQ/CdfFz5gDBugoe
         1bL/Igu4xTxbhkLdHsT8431lno2tPPPnXTqCI2Vqw9GbmN+FdK4ityrAgDp5Tn/yGGR4
         OFEWlk/+bQEKvL2QPbRnSS/8uLY3X3AzP+jnmDLkwmqOphYh4wYX9Tdv+oGbaEhbDDVO
         KZWv8LxNpEAXR+UQo0GKXCjBAinalXWnuVUitAGTOpeSfcpdznawSMXNN6rOnikvV0X9
         lu4A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703112650; x=1703717450; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HkuI0atpU9ui9BcXsHGFnzK7SNzuubvibu6xb00ZgWQ=;
        b=QF7aehTBS+tP2iTrDr8fcvMMHCB8HGwffmBZbb+ge596r/X04sAHaY731dzKQxK6/W
         0361z+Q6o8CmXh8ifnZ7eJ3kd92gZ7rbpiC1sXqRsxkzumYiamn82CW1wNDSoF7Go29a
         Yu9DzjKeaCajcSmbrCMhyjycoE3Jg4Ezo1axrWGzzle4XNOyPSfDeUzZw/zQCAfr+MHT
         95W4fPhssP9KRTodnFGGDBGVAXBJBkllV4JT7Xmw14WstbrI0M+oPcLMiUO43IWwC+wI
         bF3EA+S7t3h27PmuNA4HcxC8jJQKYnUAxfNawpDBGnUyw8AUXF3L7SfV3/7sp/2Ks52L
         5gvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703112650; x=1703717450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HkuI0atpU9ui9BcXsHGFnzK7SNzuubvibu6xb00ZgWQ=;
        b=HIJp/WUxYzrmfnOJTGi29ml5sEwzC47+WHHimcXo/MDUzFCn6QpAplKXUGexxGqF8T
         ysZJF9ha6OWrc8winxnCjleGKyI43H+qT9u2WTLitqkzCoE3Yd9OI6nhC18W4awaxUaf
         8q3U4UmP9US34kEGGEUjPHkplezDGjryENGTqnFFN3s8hn3RFrGaywHz4UgT2zawO8Df
         LWtZt3hXYQhuaV/jrlp7XUPMaXUWGoPnusilRhdEMDtMAypyNH/yKpkO5AdHXPdcaSg2
         tWpEMt5kXNRM2yN13BI7RpnH9yZY2o53wsvv0YM/jpaPFwNjDYMwfdbUbtJ+fTm2Z072
         39fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxIwsg+U+lTi9yz00GW7dNBBuJPx91+dmggSTMrM+5VhfiPfp/y
	TK9AqTvLqMNWwnIJzz0EYW8=
X-Google-Smtp-Source: AGHT+IFpiUhRI3rI+vU6JvvwjjFXLPwtpYNrQJTpsxk8TruxJZobD5YACCGS1O2aaSRIFyY31yjQpw==
X-Received: by 2002:ac8:58cf:0:b0:427:9036:424e with SMTP id u15-20020ac858cf000000b004279036424emr1741067qta.57.1703112649868;
        Wed, 20 Dec 2023 14:50:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:15cd:b0:427:6873:9b80 with SMTP id
 d13-20020a05622a15cd00b0042768739b80ls381123qty.2.-pod-prod-00-us; Wed, 20
 Dec 2023 14:50:49 -0800 (PST)
X-Received: by 2002:a05:620a:26a7:b0:77e:fcd4:aec with SMTP id c39-20020a05620a26a700b0077efcd40aecmr7224579qkp.54.1703112649078;
        Wed, 20 Dec 2023 14:50:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703112649; cv=none;
        d=google.com; s=arc-20160816;
        b=SkWYbXRca6OP1OfPowqS1zXcaoKtZcafFd49BAzzqK+IDx/YVEKHjhdSJU1qx9OLra
         saY46C5ugG53B1OIelMBG1eGhOofhle3+GRx6w73fw2kN09F2+0NGJ9xHbJJqWZX6IcN
         G3FR5E7lB0P07DXt3jEmcACoImzde+t5CXBGntPnHtpN7L4++Azn9CV69IWPbg4DbLIe
         G54Erz1QUXmYU/2vAp43izwQm4Q5gv61EOaxnAk+8qE65ZgxPcTQHQmGKdwupTw5GRhS
         nooenzrthgOHjiuC97K5GXuHZbC04rOte+NJCiAGpY1ipkn9M4tKRwKL25NyYUWgO6c/
         3v4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Gpyi7pAg6RwKMUxFGeoSuNOYareWJGta7XEGBsWJMwA=;
        fh=49O59YDaPrqO8qZGRPL9x8BJHS/UXHHGBJd7UgkdYDk=;
        b=gH9F2bc282hsp/ZvLrmU1mkxVg6SUX5iEGfOmm1bX9b7+/lwibOPHs4YN/N6LcplSu
         qHYY48gT/dhIrHvDccnvqhz36wWtoiQpJpgwfS61JvHZNFh/UoPmFjT0rQkze4EFRD6j
         h7tw+niGzpPxCqRVHvMN1C4DkGkllel/3EBL1G20ZYCEezv/Ke1gq3/4m4ZN8x7jT4ba
         QRx9SJCwoKbn0CosmtS9UXvfbqlLEpZXySgqhzfSB5Qal4600bj/HdIUGuOZ/E5zWn+l
         DIVODK8Yv+AfsaOPP8aCu159rkBFYUNRU1wC0xNhMkPZQsnss06BVrRDrUULcxVoOnEI
         QakQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dVmXacB0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id ul26-20020a05620a6d1a00b0077f3d2c7a9bsi56979qkn.7.2023.12.20.14.50.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Dec 2023 14:50:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-28bc20cb501so993107a91.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Dec 2023 14:50:49 -0800 (PST)
X-Received: by 2002:a17:90a:aa87:b0:28b:ec53:4019 with SMTP id
 l7-20020a17090aaa8700b0028bec534019mr308806pjq.17.1703112648300; Wed, 20 Dec
 2023 14:50:48 -0800 (PST)
MIME-Version: 1.0
References: <CA+fCnZdeMfx4Y-+tNcnDzNYj6fJ9pFMApLQD93csftCFV7zSow@mail.gmail.com>
 <ZM06vS0JrAVBYv2x@arm.com>
In-Reply-To: <ZM06vS0JrAVBYv2x@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 20 Dec 2023 23:50:37 +0100
Message-ID: <CA+fCnZcEj8Gm-Q51TXMr84jF5sRUko8mbOYgvz_tERpb4ijTnw@mail.gmail.com>
Subject: Re: MTE false-positive with shared userspace/kernel mapping
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Florian Mayer <fmayer@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Willem de Bruijn <willemdebruijn.kernel@gmail.com>, Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dVmXacB0;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Aug 4, 2023 at 7:52=E2=80=AFPM Catalin Marinas <catalin.marinas@arm=
.com> wrote:
>
> Hi Andrey,
>
> On Thu, Jul 20, 2023 at 08:28:12PM +0200, Andrey Konovalov wrote:
> > Syzbot reported an issue originating from the packet sockets code [1],
> > but it seems to be an MTE false-positive with a shared
> > userspace/kernel mapping.
> >
> > The problem is that mmap_region calls arch_validate_flags to check
> > VM_MTE_ALLOWED only after mapping memory for a non-anonymous mapping
> > via call_mmap().
>
> That was on purpose as we can have some specific mmap implementation
> that can set VM_MTE_ALLOWED. We only do this currently for shmem_mmap().
> But I haven't thought of the vm_insert_page() case.
>
> > What happens in the reproducer [2] is:
> >
> > 1. Userspace creates a packet socket and makes the kernel allocate the
> > backing memory for a shared mapping via alloc_one_pg_vec_page.
> > 2. Userspace calls mmap _with PROT_MTE_ on a packet socket file descrip=
tor.
> > 3. mmap code sets VM_MTE via calc_vm_prot_bits(), as PROT_MTE has been =
provided.
> > 3. mmap code calls the packet socket mmap handler packet_mmap via
> > call_mmap() (without checking VM_MTE_ALLOWED at this point).
> > 4. Packet socket code uses vm_insert_page to map the memory allocated
> > in step #1 to the userspace area.
> > 5. arm64 code resets memory tags for the backing memory via
> > vm_insert_page->...->__set_pte_at->mte_sync_tags(), as the memory is
> > MT_NORMAL_TAGGED due to VM_MTE.
> > 6. Only now the mmap code checks VM_MTE_ALLOWED via
> > arch_validate_flags() and unmaps the area, but the memory tags have
> > already been reset.
> > 5. The packet socket code accesses the area through its tagged kernel
> > address via __packet_get_status(), which leads to a tag mismatch.
>
> Ah, so we end up rejecting the mmap() eventually but the damage was done
> by clearing the tags on the kernel page via a brief set_pte_at(). I
> assume the problem only triggers with kasan enabled, though even without
> kasan, we shouldn't allow a set_pte_at(PROT_MTE) for a vma that does not
> allow MTE.
>
> > I'm not sure what would be the best fix here. Moving
> > arch_validate_flags() before call_mmap() would be an option, but maybe
> > you have a better suggestion.
>
> This would break the shmem case (though not sure who's using that). Also
> since many drivers do vm_flags_set() (unrelated to MTE), it makes more
> sense for arch_validate_flags() to happen after call_mmap().
>
> Not ideal but an easy fix is calling arch_validate_flags() in those
> specific mmap functions that call vm_insert_page(). They create a
> mapping before the core code had a chance to validate the flags. Unless
> we find a different solution for shmem_mmap() so that we can move the
> arch_validate_flags() earlier.

Just FTR: filed a KASAN bug to not forget about this issue:

https://bugzilla.kernel.org/show_bug.cgi?id=3D218295

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcEj8Gm-Q51TXMr84jF5sRUko8mbOYgvz_tERpb4ijTnw%40mail.gmai=
l.com.
