Return-Path: <kasan-dev+bncBAABB24M3S4AMGQEIBE7EZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 39FBB9A95C4
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:57:01 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5eb9fe126f8sf2302489eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:57:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562220; cv=pass;
        d=google.com; s=arc-20240605;
        b=lPX7JzmSRp9WEefIYyZWdloDvITG3iR6NgbInxHP4MMdls7UaUgTTB7rBj/4FuhbQD
         1aJOL/PXlCWGPjFKByY9m1gDX9osU/wShqKGMsg56ilgeJz8feDlFm/Q6q5NjyzrukxN
         KGBSY3JVHblWA2JoUjRfmyOxE1Bn57cq9QiDy69DszxBQ+GAsxWgvlIe1ITDBifTXf64
         2lB+cCSb3Z+u+Ja5x/0248yvXnhC2tQ6V+kSXtCxWNg04FP/P8U+7xXtsWnTFzGfY1bh
         aoC9/PzPchZkxIh0nwt4OksxSq9IwRbBz6jx0X0p6JtQi3/F+c1jigf795V2TiG/frg9
         w8uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=koEh9wfZyNhCmcz+WqRi4rIBzjuhZeYIQrQg20LovB0=;
        fh=wTVhchYUtYJUwVW6L/agd0UgS+UymVQTfu8qyslTn4I=;
        b=fk1tPzAVytVqt37kxumzHQGj0SGU1Vt1nC1FNra7vD48ONoGcKtkOBqtQpLAzynJH+
         W1Se643ZH8Ir3T7bK1emBjTHlar3rB8U6UmB9xZgIsOejOCFZsFgU/INBPLe6GQQ3eP1
         Dnhz4Rb0JzASsFJXywhrpt7XhPc8raqR0tvCKZNHRucVOQx1Mo7sVRJchUnyZQT8BNnX
         aClcfdqJ26j3jQQsyxOSCRrrlKNSffnZE+IonUcV382Dpg1mkPgZHh/EbToVeZRQbAnT
         0FItIxEDzK7FmBzYyVbkMaQMSo0ytEoLO8WxkZo6MaYUkYDXh3f/00nk0ti6DNZQLx5i
         kj/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q7oXHInr;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562220; x=1730167020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=koEh9wfZyNhCmcz+WqRi4rIBzjuhZeYIQrQg20LovB0=;
        b=f3US1oKzGTt15PZmAaqhZpsOKfw4h3jaE+yoZSJqUqe++bQE9ConPL/nSe6TfuHCaL
         bzq11OfRh+yZhVGJMDKljFhaMQmRViPLrvXwpxU/GjhQS/pUp0V6ob5qZ+HM7OdJFZg+
         VlWWlRdgS5HDW+ZoaZti1jGHXWEZcnDAuCzuqOcEqUj5hUfIPzsm4MG4TFq+SPdN7m8b
         +6UC8E87Pd3Gh2YRyj1OUt9zy03a9f0P7PkWHoG4Pm7LylzqQwJZGiaiMXIx9pVTyois
         sCqaifT2hdYuWYVcwx5QuPZ9Pwwyckgz0TmI5bn94PPeO/HznyB0UPqvbCVJwAuuRGXl
         sGaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562220; x=1730167020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=koEh9wfZyNhCmcz+WqRi4rIBzjuhZeYIQrQg20LovB0=;
        b=F3KJqHAJhiBh2Vn/kjxTz2kBab6gLFNCDf4RbC0AeDfdIrqOzsx0UsCRHqvWoOWCu9
         YxP+67ZQEG0Q1EWB+rZpBLOu/i92If+bKCdjmW+viu+FDr+F+1HOkkVHjFBJWfYOH94b
         Vk5rlyjS9Vvp8cxlw1cw8HRveZ/IWVdDb0KBAomcXei0Pk3OaxeEGrjQbdkMidrZDoJI
         dzNvictzC+b1LhTBl2ejQm/qwNhr9gJCxh1QG8V0wtxvLsHCkeIglLWTaMjVAReQjsW5
         Pcv6H3//MBHsDM604iXds4EWTgMy3WYera/r7i8NqLjOvbGXnrdshs53kbr2pfg6Evzl
         9GIA==
X-Forwarded-Encrypted: i=2; AJvYcCXdUgyn5PcOWwFF+3XmtEMu6orhCNCR6frHU7/+jFyVnOdQ0n/7rDRc1Q5NQk5A0z7MAtb1VQ==@lfdr.de
X-Gm-Message-State: AOJu0YwXuMksY9d6DPWy6i1kpFRALg3fznM35AfwfHYocbdpe9HkkUTZ
	KqXUYY1yI9L48EY0Ia88+bp8I9iQiZE944ki/w8Vjpz4UFlEJXca
X-Google-Smtp-Source: AGHT+IGzB3iibhylIS7/vhhDsLqPvavb343iuoYmvh2NYG2SV5uvktXYKyu8i22YHZo6RMiazjTOZw==
X-Received: by 2002:a05:6820:308d:b0:5e7:c8d9:9606 with SMTP id 006d021491bc7-5eb8b0a48ebmr7791310eaf.0.1729562219798;
        Mon, 21 Oct 2024 18:56:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:80c:b0:5eb:ab34:cc2c with SMTP id
 006d021491bc7-5ebab34ce17ls1319344eaf.2.-pod-prod-07-us; Mon, 21 Oct 2024
 18:56:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV9zmDQbnd++j9m46Aw/s1UjcQT9yAxFdiXT1TswwNs1MoX9VeS5ckhNBYhi/YV0YDsy13bQ06DjKg=@googlegroups.com
X-Received: by 2002:a05:6830:6618:b0:718:15a9:505f with SMTP id 46e09a7af769-7181a71775bmr14155064a34.14.1729562218851;
        Mon, 21 Oct 2024 18:56:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562218; cv=none;
        d=google.com; s=arc-20240605;
        b=LfkBMFDE9eK/EKbzS1sDBg3q0yoXKZEDeDY0dN0OCxYXWDERhYpJxzt42QSd1Jg16x
         6N9azlSlLuiCq+J6y96Dq51bZNH31XnebqOxi6xNTNlzq7jP+eRiTnSgtejfXyOUQd9S
         E2Zs76mKt963jPACx0dQAD9cW5jBhVarxjx5EKW8wRu5aSMrerqlV3mVQIuxc+hl9Whz
         gor1x3lW4ZQczMKkc3cTcawABMTTru03r0xRS5fzDf63KYHL/BNbVSqt1rRnqXmxmUGL
         ZKF2081X2+8Xid/txsUhcKIiqS0EWIqoNJ0qK1rFM5j43Pe2SegAPYtf4okAAUK/VX6R
         oAzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1B0seAFcxhqUhc3gTmx+nmAM7oPrlSTgCFT53LulqjU=;
        fh=pE712xBX0FjnO4qO2qBCh/ks8CI81xKNiG66HTAioqc=;
        b=hmiE3eHBBLHXSNB9SG2NAGwT0r3SPJaQ8oOBokMnjg2Jrzbp0WbM3LcAY0Fk5jV4hO
         IdK7NAJOuQcu6aqJvZGATvPXzi+mabyxtY927LRQobGphed+P1T7EhykkOtSXzofqV3c
         UOAHQ5UqtFo7706yReuT6W7WV+7unTbUNv9bEMygD9PB6ih/ALnFLdnf5ejV6hNAj8CP
         bppaVUi7rZKcfP0Vm7ob49yPAFB1HyHE9KtRktCzlNvm5IfhGWU8MVJNuPKol76X6Psz
         t3J4V+HqkEE5tB5KO2wfMo3CwW+CmgujDJFvNHvNHsxtUviIM/hv2gpmTmDjvCfM3cCe
         W3FQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=q7oXHInr;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7182eb2dae6si151741a34.1.2024.10.21.18.56.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:56:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C1DEA5C5C2D
	for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2024 01:56:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DD19FC4CECD
	for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2024 01:56:57 +0000 (UTC)
Received: by mail-ed1-f53.google.com with SMTP id 4fb4d7f45d1cf-5c99be0a4bbso6841015a12.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:56:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxYE2+khIH/rRgKAmT4Vt5lBmJ27StB5QhgOTjGvcjYVeK6YtFrtGa+js0EwGDaLCeA0Cb2Bek/Rk=@googlegroups.com
X-Received: by 2002:a17:907:a4a:b0:a9a:5a14:b8d8 with SMTP id
 a640c23a62f3a-a9aa8a05ebcmr185074666b.43.1729562216407; Mon, 21 Oct 2024
 18:56:56 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-2-maobibo@loongson.cn>
 <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
 <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn> <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
 <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn> <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
 <5f76ede6-e8be-c7a9-f957-479afa2fb828@loongson.cn> <CAAhV-H51W3ZRNxUjeAx52j6Tq18CEhB3_YeSH=psjAbEJUdwgg@mail.gmail.com>
 <f727e384-6989-0942-1cc8-7188f558ee39@loongson.cn> <CAAhV-H5CADad2EGv0zMQrgrvpNRtBTWDoXFj=j+zXEJdy7HkAQ@mail.gmail.com>
 <33d6cb6b-834b-f9b8-df28-b15243994f9b@loongson.cn>
In-Reply-To: <33d6cb6b-834b-f9b8-df28-b15243994f9b@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Oct 2024 09:56:43 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6gis1oSYUQJ3BzQL1qafPBj_nbBNq8arAxEJvJG7S6aQ@mail.gmail.com>
Message-ID: <CAAhV-H6gis1oSYUQJ3BzQL1qafPBj_nbBNq8arAxEJvJG7S6aQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: maobibo <maobibo@loongson.cn>
Cc: wuruiyang@loongson.cn, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=q7oXHInr;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

On Tue, Oct 22, 2024 at 9:40=E2=80=AFAM maobibo <maobibo@loongson.cn> wrote=
:
>
>
>
> On 2024/10/21 =E4=B8=8B=E5=8D=886:13, Huacai Chen wrote:
> > On Mon, Oct 21, 2024 at 9:23=E2=80=AFAM maobibo <maobibo@loongson.cn> w=
rote:
> >>
> >>
> >>
> >> On 2024/10/18 =E4=B8=8B=E5=8D=882:32, Huacai Chen wrote:
> >>> On Fri, Oct 18, 2024 at 2:23=E2=80=AFPM maobibo <maobibo@loongson.cn>=
 wrote:
> >>>>
> >>>>
> >>>>
> >>>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:23, Huacai Chen wrote:
> >>>>> On Fri, Oct 18, 2024 at 12:16=E2=80=AFPM maobibo <maobibo@loongson.=
cn> wrote:
> >>>>>>
> >>>>>>
> >>>>>>
> >>>>>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
> >>>>>>> On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongso=
n.cn> wrote:
> >>>>>>>>
> >>>>>>>>
> >>>>>>>>
> >>>>>>>> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
> >>>>>>>>> Hi, Bibo,
> >>>>>>>>>
> >>>>>>>>> I applied this patch but drop the part of arch/loongarch/mm/kas=
an_init.c:
> >>>>>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linu=
x-loongson.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ce=
d50afc403067
> >>>>>>>>>
> >>>>>>>>> Because kernel_pte_init() should operate on page-table pages, n=
ot on
> >>>>>>>>> data pages. You have already handle page-table page in
> >>>>>>>>> mm/kasan/init.c, and if we don't drop the modification on data =
pages
> >>>>>>>>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if K=
ASAN is
> >>>>>>>>> enabled.
> >>>>>>>>>
> >>>>>>>> static inline void set_pte(pte_t *ptep, pte_t pteval)
> >>>>>>>>       {
> >>>>>>>>             WRITE_ONCE(*ptep, pteval);
> >>>>>>>> -
> >>>>>>>> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
> >>>>>>>> -               pte_t *buddy =3D ptep_buddy(ptep);
> >>>>>>>> -               /*
> >>>>>>>> -                * Make sure the buddy is global too (if it's !n=
one,
> >>>>>>>> -                * it better already be global)
> >>>>>>>> -                */
> >>>>>>>> -               if (pte_none(ptep_get(buddy))) {
> >>>>>>>> -#ifdef CONFIG_SMP
> >>>>>>>> -                       /*
> >>>>>>>> -                        * For SMP, multiple CPUs can race, so w=
e need
> >>>>>>>> -                        * to do this atomically.
> >>>>>>>> -                        */
> >>>>>>>> -                       __asm__ __volatile__(
> >>>>>>>> -                       __AMOR "$zero, %[global], %[buddy] \n"
> >>>>>>>> -                       : [buddy] "+ZB" (buddy->pte)
> >>>>>>>> -                       : [global] "r" (_PAGE_GLOBAL)
> >>>>>>>> -                       : "memory");
> >>>>>>>> -
> >>>>>>>> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >>>>>>>> -#else /* !CONFIG_SMP */
> >>>>>>>> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_ge=
t(buddy)) | _PAGE_GLOBAL));
> >>>>>>>> -#endif /* CONFIG_SMP */
> >>>>>>>> -               }
> >>>>>>>> -       }
> >>>>>>>> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> >>>>>>>>       }
> >>>>>>>>
> >>>>>>>> No, please hold on. This issue exists about twenty years, Do we =
need be
> >>>>>>>> in such a hurry now?
> >>>>>>>>
> >>>>>>>> why is DBAR(0b11000) added in set_pte()?
> >>>>>>> It exists before, not added by this patch. The reason is explaine=
d in
> >>>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.gi=
t/commit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
> >>>>>> why speculative accesses may cause spurious page fault in kernel s=
pace
> >>>>>> with PTE enabled?  speculative accesses exists anywhere, it does n=
ot
> >>>>>> cause spurious page fault.
> >>>>> Confirmed by Ruiyang Wu, and even if DBAR(0b11000) is wrong, that
> >>>>> means another patch's mistake, not this one. This one just keeps th=
e
> >>>>> old behavior.
> >>>>> +CC Ruiyang Wu here.
> >>>> Also from Ruiyang Wu, the information is that speculative accesses m=
ay
> >>>> insert stale TLB, however no page fault exception.
> >>>>
> >>>> So adding barrier in set_pte() does not prevent speculative accesses=
.
> >>>> And you write patch here, however do not know the actual reason?
> >>>>
> >>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/c=
ommit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
> >>> I have CCed Ruiyang, whether the description is correct can be judged=
 by him.
> >>
> >> There are some problems to add barrier() in set_pte():
> >>
> >> 1. There is such issue only for HW ptw enabled and kernel address spac=
e,
> >> is that? Also it may be two heavy to add barrier in set_pte(), compari=
ng
> >> to do this in flush_cache_vmap().
> > So adding a barrier in set_pte() may not be the best solution for
> > performance, but you cannot say it is a wrong solution. And yes, we
> > can only care the kernel space, which is also the old behavior before
> > this patch, so set_pte() should be:
> >
> > static inline void set_pte(pte_t *ptep, pte_t pteval)
> > {
> >          WRITE_ONCE(*ptep, pteval);
> > #ifdef CONFIG_SMP
> >          if (pte_val(pteval) & _PAGE_GLOBAL)
> cpu_has_ptw seems also need here, if it is only for hw page walk.
> >                  DBAR(0b11000); /* o_wrw =3D 0b11000 */
> > #endif
> > }
> >
> > Putting a dbar unconditionally in set_pte() is my mistake, I'm sorry fo=
r  that.
> >
> >>
> >> 2. LoongArch is different with other other architectures, two pages ar=
e
> >> included in one TLB entry. If there is two consecutive page mapped and
> >> memory access, there will page fault for the second memory access. Suc=
h
> >> as:
> >>      addr1 =3Dpercpu_alloc(pagesize);
> >>      val1 =3D *(int *)addr1;
> >>        // With page table walk, addr1 is present and addr2 is pte_none
> >>        // TLB entry includes valid pte for addr1, invalid pte for addr=
2
> >>      addr2 =3Dpercpu_alloc(pagesize); // will not flush tlb in first t=
ime
> >>      val2 =3D *(int *)addr2;
> >>        // With page table walk, addr1 is present and addr2 is present =
also
> >>        // TLB entry includes valid pte for addr1, invalid pte for addr=
2
> >>      So there will be page fault when accessing address addr2
> >>
> >> There there is the same problem with user address space. By the way,
> >> there is HW prefetching technology, negative effective of HW prefetchi=
ng
> >> technology will be tlb added. So there is potential page fault if memo=
ry
> >> is allocated and accessed in the first time.
> > As discussed internally, there may be three problems related to
> > speculative access in detail: 1) a load/store after set_pte() is
> > prioritized before, which can be prevented by dbar, 2) a instruction
> > fetch after set_pte() is prioritized before, which can be prevented by
> > ibar, 3) the buddy tlb problem you described here, if I understand
> > Ruiyang's explanation correctly this can only be prevented by the
> > filter in do_page_fault().
> >
> >  From experiments, without the patch "LoongArch: Improve hardware page
> > table walker", there are about 80 times of spurious page faults during
> > boot, and increases continually during stress tests. And after that
> > patch which adds a dbar to set_pte(), we cannot observe spurious page
> > faults anymore. Of course this doesn't mean 2) and 3) don't exist, but
> Good experiment result. Could you share me code about page fault
> counting and test cases?
Counting method:
1, Add a simple printk at the beginning of spurious_fault(), and count
the number of printk from dmesg.
2, Test case: boot Fedora to desktop, and then run kernel building
work with "make -j8" in the system.

Huacai

>
> > we can at least say 1) is the main case. On this basis, in "LoongArch:
> > Improve hardware page table walker" we use a relatively cheap dbar
> > (compared to ibar) to prevent the main case, and add a filter to
> > handle 2) and 3). Such a solution is reasonable.
> >
> >
> >>
> >> 3. For speculative execution, if it is user address, there is eret fro=
m
> >> syscall. eret will rollback all speculative execution instruction. So =
it
> >> is only problem for speculative execution. And how to verify whether i=
t
> >> is the problem of speculative execution or it is the problem of clause=
 2?
> > As described above, if spurious page faults still exist after adding
> > dbar to set_pte(), it may be a problem of clause 2 (case 3 in my
> > description), otherwise it is not a problem of clause 2.
> >
> > At last, this patch itself is attempting to solve the concurrent
> > problem about _PAGE_GLOBAL, so adding pte_alloc_one_kernel() and
> > removing the buddy stuff in set_pte() are what it needs. However it
> > shouldn't touch the logic of dbar in set_pte(), whether "LoongArch:
> > Improve hardware page table walker" is right or wrong.
> yes, I agree. We can discuss set_pte() issue in later. Simple for this
> patch to solve concurrent problem, it is ok
> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongson=
.git/diff/mm/kasan/init.c?h=3Dloongarch-next&id=3D15832255e84494853f543b4c7=
0ced50afc403067
>
> Regards
> Bibo Mao
> >
> >
> > Huacai
> >
> >>
> >> Regards
> >> Bibo Mao
> >>
> >>
> >>>
> >>> Huacai
> >>>
> >>>>
> >>>> Bibo Mao
> >>>>>
> >>>>> Huacai
> >>>>>
> >>>>>>
> >>>>>> Obvious you do not it and you write wrong patch.
> >>>>>>
> >>>>>>>
> >>>>>>> Huacai
> >>>>>>>
> >>>>>>>>
> >>>>>>>> Regards
> >>>>>>>> Bibo Mao
> >>>>>>>>> Huacai
> >>>>>>>>>
> >>>>>>>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loon=
gson.cn> wrote:
> >>>>>>>>>>
> >>>>>>>>>> Unlike general architectures, there are two pages in one TLB e=
ntry
> >>>>>>>>>> on LoongArch system. For kernel space, it requires both two pt=
e
> >>>>>>>>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-glo=
bal
> >>>>>>>>>> tlb, there will be potential problems if tlb entry for kernel =
space
> >>>>>>>>>> is not global. Such as fail to flush kernel tlb with function
> >>>>>>>>>> local_flush_tlb_kernel_range() which only flush tlb with globa=
l bit.
> >>>>>>>>>>
> >>>>>>>>>> With function kernel_pte_init() added, it can be used to init =
pte
> >>>>>>>>>> table when it is created for kernel address space, and the def=
ault
> >>>>>>>>>> initial pte value is PAGE_GLOBAL rather than zero at beginning=
.
> >>>>>>>>>>
> >>>>>>>>>> Kernel address space areas includes fixmap, percpu, vmalloc, k=
asan
> >>>>>>>>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
> >>>>>>>>>>
> >>>>>>>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> >>>>>>>>>> ---
> >>>>>>>>>>       arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
> >>>>>>>>>>       arch/loongarch/include/asm/pgtable.h |  1 +
> >>>>>>>>>>       arch/loongarch/mm/init.c             |  4 +++-
> >>>>>>>>>>       arch/loongarch/mm/kasan_init.c       |  4 +++-
> >>>>>>>>>>       arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++=
++++++++
> >>>>>>>>>>       include/linux/mm.h                   |  1 +
> >>>>>>>>>>       mm/kasan/init.c                      |  8 +++++++-
> >>>>>>>>>>       mm/sparse-vmemmap.c                  |  5 +++++
> >>>>>>>>>>       8 files changed, 55 insertions(+), 3 deletions(-)
> >>>>>>>>>>
> >>>>>>>>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loong=
arch/include/asm/pgalloc.h
> >>>>>>>>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
> >>>>>>>>>> --- a/arch/loongarch/include/asm/pgalloc.h
> >>>>>>>>>> +++ b/arch/loongarch/include/asm/pgalloc.h
> >>>>>>>>>> @@ -10,8 +10,21 @@
> >>>>>>>>>>
> >>>>>>>>>>       #define __HAVE_ARCH_PMD_ALLOC_ONE
> >>>>>>>>>>       #define __HAVE_ARCH_PUD_ALLOC_ONE
> >>>>>>>>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
> >>>>>>>>>>       #include <asm-generic/pgalloc.h>
> >>>>>>>>>>
> >>>>>>>>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *m=
m)
> >>>>>>>>>> +{
> >>>>>>>>>> +       pte_t *pte;
> >>>>>>>>>> +
> >>>>>>>>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
> >>>>>>>>>> +       if (!pte)
> >>>>>>>>>> +               return NULL;
> >>>>>>>>>> +
> >>>>>>>>>> +       kernel_pte_init(pte);
> >>>>>>>>>> +       return pte;
> >>>>>>>>>> +}
> >>>>>>>>>> +
> >>>>>>>>>>       static inline void pmd_populate_kernel(struct mm_struct =
*mm,
> >>>>>>>>>>                                             pmd_t *pmd, pte_t =
*pte)
> >>>>>>>>>>       {
> >>>>>>>>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loong=
arch/include/asm/pgtable.h
> >>>>>>>>>> index 9965f52ef65b..22e3a8f96213 100644
> >>>>>>>>>> --- a/arch/loongarch/include/asm/pgtable.h
> >>>>>>>>>> +++ b/arch/loongarch/include/asm/pgtable.h
> >>>>>>>>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *m=
m, unsigned long addr, pmd_t *pmdp, pm
> >>>>>>>>>>       extern void pgd_init(void *addr);
> >>>>>>>>>>       extern void pud_init(void *addr);
> >>>>>>>>>>       extern void pmd_init(void *addr);
> >>>>>>>>>> +extern void kernel_pte_init(void *addr);
> >>>>>>>>>>
> >>>>>>>>>>       /*
> >>>>>>>>>>        * Encode/decode swap entries and swap PTEs. Swap PTEs a=
re all PTEs that
> >>>>>>>>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init=
.c
> >>>>>>>>>> index 8a87a482c8f4..9f26e933a8a3 100644
> >>>>>>>>>> --- a/arch/loongarch/mm/init.c
> >>>>>>>>>> +++ b/arch/loongarch/mm/init.c
> >>>>>>>>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsign=
ed long addr)
> >>>>>>>>>>              if (!pmd_present(pmdp_get(pmd))) {
> >>>>>>>>>>                      pte_t *pte;
> >>>>>>>>>>
> >>>>>>>>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> >>>>>>>>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZ=
E);
> >>>>>>>>>>                      if (!pte)
> >>>>>>>>>>                              panic("%s: Failed to allocate mem=
ory\n", __func__);
> >>>>>>>>>> +
> >>>>>>>>>> +               kernel_pte_init(pte);
> >>>>>>>>>>                      pmd_populate_kernel(&init_mm, pmd, pte);
> >>>>>>>>>>              }
> >>>>>>>>>>
> >>>>>>>>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/m=
m/kasan_init.c
> >>>>>>>>>> index 427d6b1aec09..34988573b0d5 100644
> >>>>>>>>>> --- a/arch/loongarch/mm/kasan_init.c
> >>>>>>>>>> +++ b/arch/loongarch/mm/kasan_init.c
> >>>>>>>>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_=
t *pmdp, unsigned long addr,
> >>>>>>>>>>                      phys_addr_t page_phys =3D early ?
> >>>>>>>>>>                                              __pa_symbol(kasan=
_early_shadow_page)
> >>>>>>>>>>                                                    : kasan_all=
oc_zeroed_page(node);
> >>>>>>>>>> +               if (!early)
> >>>>>>>>>> +                       kernel_pte_init(__va(page_phys));
> >>>>>>>>>>                      next =3D addr + PAGE_SIZE;
> >>>>>>>>>>                      set_pte(ptep, pfn_pte(__phys_to_pfn(page_=
phys), PAGE_KERNEL));
> >>>>>>>>>>              } while (ptep++, addr =3D next, addr !=3D end && =
__pte_none(early, ptep_get(ptep)));
> >>>>>>>>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
> >>>>>>>>>>                      set_pte(&kasan_early_shadow_pte[i],
> >>>>>>>>>>                              pfn_pte(__phys_to_pfn(__pa_symbol=
(kasan_early_shadow_page)), PAGE_KERNEL_RO));
> >>>>>>>>>>
> >>>>>>>>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> >>>>>>>>>> +       kernel_pte_init(kasan_early_shadow_page);
> >>>>>>>>>>              csr_write64(__pa_symbol(swapper_pg_dir), LOONGARC=
H_CSR_PGDH);
> >>>>>>>>>>              local_flush_tlb_all();
> >>>>>>>>>>
> >>>>>>>>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/p=
gtable.c
> >>>>>>>>>> index eb6a29b491a7..228ffc1db0a3 100644
> >>>>>>>>>> --- a/arch/loongarch/mm/pgtable.c
> >>>>>>>>>> +++ b/arch/loongarch/mm/pgtable.c
> >>>>>>>>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
> >>>>>>>>>>       }
> >>>>>>>>>>       EXPORT_SYMBOL_GPL(pgd_alloc);
> >>>>>>>>>>
> >>>>>>>>>> +void kernel_pte_init(void *addr)
> >>>>>>>>>> +{
> >>>>>>>>>> +       unsigned long *p, *end;
> >>>>>>>>>> +       unsigned long entry;
> >>>>>>>>>> +
> >>>>>>>>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
> >>>>>>>>>> +       p =3D (unsigned long *)addr;
> >>>>>>>>>> +       end =3D p + PTRS_PER_PTE;
> >>>>>>>>>> +
> >>>>>>>>>> +       do {
> >>>>>>>>>> +               p[0] =3D entry;
> >>>>>>>>>> +               p[1] =3D entry;
> >>>>>>>>>> +               p[2] =3D entry;
> >>>>>>>>>> +               p[3] =3D entry;
> >>>>>>>>>> +               p[4] =3D entry;
> >>>>>>>>>> +               p +=3D 8;
> >>>>>>>>>> +               p[-3] =3D entry;
> >>>>>>>>>> +               p[-2] =3D entry;
> >>>>>>>>>> +               p[-1] =3D entry;
> >>>>>>>>>> +       } while (p !=3D end);
> >>>>>>>>>> +}
> >>>>>>>>>> +
> >>>>>>>>>>       void pgd_init(void *addr)
> >>>>>>>>>>       {
> >>>>>>>>>>              unsigned long *p, *end;
> >>>>>>>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
> >>>>>>>>>> index ecf63d2b0582..6909fe059a2c 100644
> >>>>>>>>>> --- a/include/linux/mm.h
> >>>>>>>>>> +++ b/include/linux/mm.h
> >>>>>>>>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long =
size);
> >>>>>>>>>>       struct page * __populate_section_memmap(unsigned long pf=
n,
> >>>>>>>>>>                      unsigned long nr_pages, int nid, struct v=
mem_altmap *altmap,
> >>>>>>>>>>                      struct dev_pagemap *pgmap);
> >>>>>>>>>> +void kernel_pte_init(void *addr);
> >>>>>>>>>>       void pmd_init(void *addr);
> >>>>>>>>>>       void pud_init(void *addr);
> >>>>>>>>>>       pgd_t *vmemmap_pgd_populate(unsigned long addr, int node=
);
> >>>>>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> >>>>>>>>>> index 89895f38f722..ac607c306292 100644
> >>>>>>>>>> --- a/mm/kasan/init.c
> >>>>>>>>>> +++ b/mm/kasan/init.c
> >>>>>>>>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t=
 *pmd, unsigned long addr,
> >>>>>>>>>>              }
> >>>>>>>>>>       }
> >>>>>>>>>>
> >>>>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>>>>>>>> +{
> >>>>>>>>>> +}
> >>>>>>>>>> +
> >>>>>>>>>>       static int __ref zero_pmd_populate(pud_t *pud, unsigned =
long addr,
> >>>>>>>>>>                                      unsigned long end)
> >>>>>>>>>>       {
> >>>>>>>>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t =
*pud, unsigned long addr,
> >>>>>>>>>>
> >>>>>>>>>>                              if (slab_is_available())
> >>>>>>>>>>                                      p =3D pte_alloc_one_kerne=
l(&init_mm);
> >>>>>>>>>> -                       else
> >>>>>>>>>> +                       else {
> >>>>>>>>>>                                      p =3D early_alloc(PAGE_SI=
ZE, NUMA_NO_NODE);
> >>>>>>>>>> +                               kernel_pte_init(p);
> >>>>>>>>>> +                       }
> >>>>>>>>>>                              if (!p)
> >>>>>>>>>>                                      return -ENOMEM;
> >>>>>>>>>>
> >>>>>>>>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> >>>>>>>>>> index edcc7a6b0f6f..c0388b2e959d 100644
> >>>>>>>>>> --- a/mm/sparse-vmemmap.c
> >>>>>>>>>> +++ b/mm/sparse-vmemmap.c
> >>>>>>>>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_blo=
ck_zero(unsigned long size, int node)
> >>>>>>>>>>              return p;
> >>>>>>>>>>       }
> >>>>>>>>>>
> >>>>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
> >>>>>>>>>> +{
> >>>>>>>>>> +}
> >>>>>>>>>> +
> >>>>>>>>>>       pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsig=
ned long addr, int node)
> >>>>>>>>>>       {
> >>>>>>>>>>              pmd_t *pmd =3D pmd_offset(pud, addr);
> >>>>>>>>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud=
_t *pud, unsigned long addr, int node)
> >>>>>>>>>>                      void *p =3D vmemmap_alloc_block_zero(PAGE=
_SIZE, node);
> >>>>>>>>>>                      if (!p)
> >>>>>>>>>>                              return NULL;
> >>>>>>>>>> +               kernel_pte_init(p);
> >>>>>>>>>>                      pmd_populate_kernel(&init_mm, pmd, p);
> >>>>>>>>>>              }
> >>>>>>>>>>              return pmd;
> >>>>>>>>>> --
> >>>>>>>>>> 2.39.3
> >>>>>>>>>>
> >>>>>>>>
> >>>>>>>>
> >>>>>>
> >>>>>>
> >>>>
> >>>>
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H6gis1oSYUQJ3BzQL1qafPBj_nbBNq8arAxEJvJG7S6aQ%40mail.gmail.=
com.
