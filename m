Return-Path: <kasan-dev+bncBAABBEG2224AMGQELO4BLYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D3299A5880
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 03:23:30 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e28edea9af6sf5714960276.3
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Oct 2024 18:23:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729473809; cv=pass;
        d=google.com; s=arc-20240605;
        b=bcONg9SFiQ8bmr59G5S1fl4W9gBH7D9jex0frZESPbWUZesBzgq35sPQp2yU3KUIHP
         UlCOZ9xRLUXKn2wE35NhRxk9spqAchRy1zcsSzPU1UVYrm0yboEBaBxRExeQ7rnAAHuY
         qOQdzZSl7G+jySt6GltYDh8hU0NcC+oSZEkdopky6EtbiQEhPn5ODDzkyS5ug0sWsSvg
         o3lSIZAFglVMqbmoZ23Y8YUQ3gMAeT7cdq3fEED4nU9Hip+zpFZyJYgEDrYNyvjPBAgl
         PPWRamIqJ2FdTAcegpAjt1H9rkRWlAtcE3GkpFtLcwGRePeqZekInZO3Gx5GUwUnIHqO
         eIbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=XziqZvUE9e7lbvKIPBpQ7R7rqNFviSiYtKjqcb7V8mw=;
        fh=wHSGcbM1CLu8ICnAViDZ7KYjmEWCwpnmg3zAqEe1AW0=;
        b=bFHgYXbg6d59p8lOtbBAWCZlqK4qA35Y+5EtxRK+GXWcGdirol284tmph4nCUiLkpt
         taVaj7g6m2hIpcmwZ6yf36qxyJRR5iRT3qmxNLGSnN+temuSgoOXciyuDvHIsv+LbL5U
         vunI7jplcJLIe1D93KJcpbx2K6pjLnuiCeC+woVLXgCNXBFkYDl8LEZSsBMIL7IhWIiO
         cErxKgJomVj17qFt+F5AQewnOu4e/9hwd1i/iCGp0hX1lz1RbO2AW/K9mAIDL2ooW5t2
         ShdRrLRGBVwJxJufp8FOw333OSbxUvCevjZLiTOpFehU63A7W69LLCQssqEOC7vB0WTz
         csrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729473809; x=1730078609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XziqZvUE9e7lbvKIPBpQ7R7rqNFviSiYtKjqcb7V8mw=;
        b=mGC8L7LvVDZ1BecjY5BXmuj3A5oIvx6OS2TA+Dpm0SueycI2G5luJIE2SD6/3qg+YI
         0XK/FEXgLlC2hOmy3hmb2x+1NHXOrflHDX7SBhDuemXa2HDfHhRL/D2NCX8q4JbVkzKy
         t38jjpdpyXAKhou/jDwzKqoR7tEMwG0a74Pr0sQYtpAvYFz3AQH/vmeJvdoaIsISrZ7C
         EHfcXDJOITV4nnZntcJdmn6lKfTUz8gSXZWaX+/CA4vh4VleiUGqfp1Wvj759ZsaLiWh
         bpYPAZu7tp+8/n0xUOxxXNhc1BAr0t5mABJYdykswKKyB3SJZgvE1wmnLQbAvDS8iR/S
         qVSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729473809; x=1730078609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XziqZvUE9e7lbvKIPBpQ7R7rqNFviSiYtKjqcb7V8mw=;
        b=v0UrmZjHgEHduK3Ur9cks0zJVVPrzNX8zO0glnRrcpBMet4KUJ7dGLSJCsIeZ/WjZ5
         W1Q7th+Ig45I0K+ojwet/iUtvJCBs/Kpk3eHklXhRHWsQRBEeax0+xZDrytbuL7Npm3b
         3NX0rVc/bJN+YL0DuP/akQCgTwrUblkFSO1OFDmqN93fcrh37SHMhSXfhY+dPkth1Za/
         FxwG8/8vLZ0IP5nDIqiV7HvkNPRgBJyNAgeDJidbEVhV+uoz/FQfNedw/V/YajPB/ny1
         C1G6OWLz/+Wg4UmNbkoX6ldv1K8tB2FlY8ITeQl21sJueZzAADApsqh7hvKoE/ZU7KyI
         OcDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX2kEEAi/55tU6P3W0OveFlL3bQ6vDp18DY6D51dht03AiAfUpt7H7It2dyDT0Ri2wTrJ7YCw==@lfdr.de
X-Gm-Message-State: AOJu0YxpKDhibvPT0anR9jS5ca+iT5I34WqV9jdkwjaT5M2FMfeSex0e
	bX+sP56wUNXt6rvNObRp/n6/ie48RILz/OnV0Lip9gB8pJqA4Nln
X-Google-Smtp-Source: AGHT+IFgCt2RB/+17Rzx4jCiFBgmTb1vDKK5Pt5/9mKww14VP4Njl/SFfi+IhEW2oxD3aXGrE8tYHQ==
X-Received: by 2002:a25:3ac1:0:b0:e2b:c7b1:eab8 with SMTP id 3f1490d57ef6-e2bc7b2074cmr5391686276.21.1729473809023;
        Sun, 20 Oct 2024 18:23:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1243:b0:e29:2bfb:85f6 with SMTP id
 3f1490d57ef6-e2b9cdfb316ls197725276.1.-pod-prod-07-us; Sun, 20 Oct 2024
 18:23:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNxAzYQ/Jw5k/66Q83dUN73afZzZgbd7d2MYckPSua6BCTtAxiA49rXRAEmwh7++tThVyj1HIblO4=@googlegroups.com
X-Received: by 2002:a05:690c:6f0c:b0:6e3:420f:a2d1 with SMTP id 00721157ae682-6e5bfc78c7emr95594497b3.23.1729473808031;
        Sun, 20 Oct 2024 18:23:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729473808; cv=none;
        d=google.com; s=arc-20240605;
        b=QD6fvJOl/2q+b6QK5nZvozhZWPqFIoxtkBBJi2fc3H2elXTzilvl/Q8JZnSduMZGu2
         LnC980Yg6AMAycVCuNDMikRW/5JrvtzlnsgSw0EJ75WkMTVPMPtkojh4JOzYZ6j96Uxm
         OG3MWnAFdrKrFlmJ/6JcDSQC+Kv52gmM0WcR1oSmHNmOB66L/2nZQohY8UxjpsJBnMBU
         /Iuig6+5fX3i/XvKD3cbKkhjATMkHNoqAqpiSWoCJAGqOeCmiiqrFQmW2Fo5eHqn5+H/
         TYAGu1Msrtv7aPNXdDuyMwJtn2/dTK6OFwV51eUAt9c8YtclYCVnDeQKYdlhvYq5i6aw
         fe9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=S2Pdfzx5bmJ1vrAlHAwkk7gCU//ZgUJZPo7OVlihm/c=;
        fh=GN+TnQBjgabBq5rNIUtQQucUASmSQHUB4i4c84RJIVo=;
        b=b+hmZC+NKj6hUY0Gt6RFw4vkieji7cIzqTRSMFf5hItA87S4ziQNn0A8G2uTXOi6vq
         sPn/pXmJGNbLQiRCNXQVFCOWSTyf9nSh/GqwCmtMwwJv//uZ3CJ5aYSIkX5ymdBNQrlr
         vRSpTuNrKB+UEvUwz7PnIpmxAxabRtTL0niiZKAeOLpDdeyTn9udOWlvzRvwSCGWc7KY
         RyXph06PNxY4OA5AxH7LCz19dsn761Dpm4dTCXJ+W5/swSyl7FsCSbBPGkeBDlRM3eqO
         ufHBus9UIWiq5Zav8g1ODlDTfnebZjAt5N5Xepoj216iut53FC9D6vzUCaH7U0n//85V
         qHNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 00721157ae682-6e5f5cbe081si1532167b3.2.2024.10.20.18.23.26
        for <kasan-dev@googlegroups.com>;
        Sun, 20 Oct 2024 18:23:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8AxaeEMrRVnjxABAA--.2523S3;
	Mon, 21 Oct 2024 09:23:24 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMBxveAKrRVn+ckBAA--.10312S3;
	Mon, 21 Oct 2024 09:23:22 +0800 (CST)
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: Huacai Chen <chenhuacai@kernel.org>
Cc: wuruiyang@loongson.cn, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20241014035855.1119220-1-maobibo@loongson.cn>
 <20241014035855.1119220-2-maobibo@loongson.cn>
 <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com>
 <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn>
 <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
 <a4c6b89e-4ffe-4486-4ccd-7ebc28734f6f@loongson.cn>
 <CAAhV-H6FkJZwa-pALUhucrU5OXxsHg+ByM+4NN0wPQgOJTqOXA@mail.gmail.com>
 <5f76ede6-e8be-c7a9-f957-479afa2fb828@loongson.cn>
 <CAAhV-H51W3ZRNxUjeAx52j6Tq18CEhB3_YeSH=psjAbEJUdwgg@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <f727e384-6989-0942-1cc8-7188f558ee39@loongson.cn>
Date: Mon, 21 Oct 2024 09:22:59 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H51W3ZRNxUjeAx52j6Tq18CEhB3_YeSH=psjAbEJUdwgg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMBxveAKrRVn+ckBAA--.10312S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj9fXoWfJw48ZFyfWrWrtw45try3ZFc_yoW8GF1DZo
	W5JF47tr18JryUJr10y34Dtw1Utw1DKw4UArW2yr4UXF15t34UAr1UJr15XFW7Gr1rJrsr
	GFyUXr4UZrW7Jrn8l-sFpf9Il3svdjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8wcxFpf
	9Il3svdxBIdaVrn0xqx4xG64xvF2IEw4CE5I8CrVC2j2Jv73VFW2AGmfu7bjvjm3AaLaJ3
	UjIYCTnIWjp_UUUY27kC6x804xWl14x267AKxVWUJVW8JwAFc2x0x2IEx4CE42xK8VAvwI
	8IcIk0rVWrJVCq3wAFIxvE14AKwVWUXVWUAwA2ocxC64kIII0Yj41l84x0c7CEw4AK67xG
	Y2AK021l84ACjcxK6xIIjxv20xvE14v26r1j6r1xM28EF7xvwVC0I7IYx2IY6xkF7I0E14
	v26r1j6r4UM28EF7xvwVC2z280aVAFwI0_Jr0_Gr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4j6r4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc
	02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUGVWUXwAv7VC2z280aVAF
	wI0_Jr0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2IEe2xFo4
	CEbIxvr21l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG
	67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r1q6r43MI
	IYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_Jr0_JF4lIxAIcVC0I7IYx2IY6xkF7I0E
	14v26r1j6r4UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67AKxVWUJV
	W8JwCI42IY6I8E87Iv6xkF7I0E14v26r1j6r4UYxBIdaVFxhVjvjDU0xZFpf9x07jUsqXU
	UUUU=
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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



On 2024/10/18 =E4=B8=8B=E5=8D=882:32, Huacai Chen wrote:
> On Fri, Oct 18, 2024 at 2:23=E2=80=AFPM maobibo <maobibo@loongson.cn> wro=
te:
>>
>>
>>
>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:23, Huacai Chen wrote:
>>> On Fri, Oct 18, 2024 at 12:16=E2=80=AFPM maobibo <maobibo@loongson.cn> =
wrote:
>>>>
>>>>
>>>>
>>>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
>>>>> On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.cn=
> wrote:
>>>>>>
>>>>>>
>>>>>>
>>>>>> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
>>>>>>> Hi, Bibo,
>>>>>>>
>>>>>>> I applied this patch but drop the part of arch/loongarch/mm/kasan_i=
nit.c:
>>>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-lo=
ongson.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50a=
fc403067
>>>>>>>
>>>>>>> Because kernel_pte_init() should operate on page-table pages, not o=
n
>>>>>>> data pages. You have already handle page-table page in
>>>>>>> mm/kasan/init.c, and if we don't drop the modification on data page=
s
>>>>>>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN=
 is
>>>>>>> enabled.
>>>>>>>
>>>>>> static inline void set_pte(pte_t *ptep, pte_t pteval)
>>>>>>      {
>>>>>>            WRITE_ONCE(*ptep, pteval);
>>>>>> -
>>>>>> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
>>>>>> -               pte_t *buddy =3D ptep_buddy(ptep);
>>>>>> -               /*
>>>>>> -                * Make sure the buddy is global too (if it's !none,
>>>>>> -                * it better already be global)
>>>>>> -                */
>>>>>> -               if (pte_none(ptep_get(buddy))) {
>>>>>> -#ifdef CONFIG_SMP
>>>>>> -                       /*
>>>>>> -                        * For SMP, multiple CPUs can race, so we ne=
ed
>>>>>> -                        * to do this atomically.
>>>>>> -                        */
>>>>>> -                       __asm__ __volatile__(
>>>>>> -                       __AMOR "$zero, %[global], %[buddy] \n"
>>>>>> -                       : [buddy] "+ZB" (buddy->pte)
>>>>>> -                       : [global] "r" (_PAGE_GLOBAL)
>>>>>> -                       : "memory");
>>>>>> -
>>>>>> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>>>>>> -#else /* !CONFIG_SMP */
>>>>>> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(bu=
ddy)) | _PAGE_GLOBAL));
>>>>>> -#endif /* CONFIG_SMP */
>>>>>> -               }
>>>>>> -       }
>>>>>> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>>>>>>      }
>>>>>>
>>>>>> No, please hold on. This issue exists about twenty years, Do we need=
 be
>>>>>> in such a hurry now?
>>>>>>
>>>>>> why is DBAR(0b11000) added in set_pte()?
>>>>> It exists before, not added by this patch. The reason is explained in
>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/co=
mmit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
>>>> why speculative accesses may cause spurious page fault in kernel space
>>>> with PTE enabled?  speculative accesses exists anywhere, it does not
>>>> cause spurious page fault.
>>> Confirmed by Ruiyang Wu, and even if DBAR(0b11000) is wrong, that
>>> means another patch's mistake, not this one. This one just keeps the
>>> old behavior.
>>> +CC Ruiyang Wu here.
>> Also from Ruiyang Wu, the information is that speculative accesses may
>> insert stale TLB, however no page fault exception.
>>
>> So adding barrier in set_pte() does not prevent speculative accesses.
>> And you write patch here, however do not know the actual reason?
>>
>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commi=
t/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
> I have CCed Ruiyang, whether the description is correct can be judged by =
him.

There are some problems to add barrier() in set_pte():

1. There is such issue only for HW ptw enabled and kernel address space,=20
is that? Also it may be two heavy to add barrier in set_pte(), comparing=20
to do this in flush_cache_vmap().

2. LoongArch is different with other other architectures, two pages are=20
included in one TLB entry. If there is two consecutive page mapped and=20
memory access, there will page fault for the second memory access. Such
as:
    addr1 =3Dpercpu_alloc(pagesize);
    val1 =3D *(int *)addr1;
      // With page table walk, addr1 is present and addr2 is pte_none
      // TLB entry includes valid pte for addr1, invalid pte for addr2
    addr2 =3Dpercpu_alloc(pagesize); // will not flush tlb in first time
    val2 =3D *(int *)addr2;
      // With page table walk, addr1 is present and addr2 is present also
      // TLB entry includes valid pte for addr1, invalid pte for addr2
    So there will be page fault when accessing address addr2

There there is the same problem with user address space. By the way,=20
there is HW prefetching technology, negative effective of HW prefetching=20
technology will be tlb added. So there is potential page fault if memory=20
is allocated and accessed in the first time.

3. For speculative execution, if it is user address, there is eret from=20
syscall. eret will rollback all speculative execution instruction. So it=20
is only problem for speculative execution. And how to verify whether it=20
is the problem of speculative execution or it is the problem of clause 2?

Regards
Bibo Mao


>=20
> Huacai
>=20
>>
>> Bibo Mao
>>>
>>> Huacai
>>>
>>>>
>>>> Obvious you do not it and you write wrong patch.
>>>>
>>>>>
>>>>> Huacai
>>>>>
>>>>>>
>>>>>> Regards
>>>>>> Bibo Mao
>>>>>>> Huacai
>>>>>>>
>>>>>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson=
.cn> wrote:
>>>>>>>>
>>>>>>>> Unlike general architectures, there are two pages in one TLB entry
>>>>>>>> on LoongArch system. For kernel space, it requires both two pte
>>>>>>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
>>>>>>>> tlb, there will be potential problems if tlb entry for kernel spac=
e
>>>>>>>> is not global. Such as fail to flush kernel tlb with function
>>>>>>>> local_flush_tlb_kernel_range() which only flush tlb with global bi=
t.
>>>>>>>>
>>>>>>>> With function kernel_pte_init() added, it can be used to init pte
>>>>>>>> table when it is created for kernel address space, and the default
>>>>>>>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
>>>>>>>>
>>>>>>>> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
>>>>>>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
>>>>>>>>
>>>>>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>>>>>>>> ---
>>>>>>>>      arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>>>>>>>>      arch/loongarch/include/asm/pgtable.h |  1 +
>>>>>>>>      arch/loongarch/mm/init.c             |  4 +++-
>>>>>>>>      arch/loongarch/mm/kasan_init.c       |  4 +++-
>>>>>>>>      arch/loongarch/mm/pgtable.c          | 22 +++++++++++++++++++=
+++
>>>>>>>>      include/linux/mm.h                   |  1 +
>>>>>>>>      mm/kasan/init.c                      |  8 +++++++-
>>>>>>>>      mm/sparse-vmemmap.c                  |  5 +++++
>>>>>>>>      8 files changed, 55 insertions(+), 3 deletions(-)
>>>>>>>>
>>>>>>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch=
/include/asm/pgalloc.h
>>>>>>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
>>>>>>>> --- a/arch/loongarch/include/asm/pgalloc.h
>>>>>>>> +++ b/arch/loongarch/include/asm/pgalloc.h
>>>>>>>> @@ -10,8 +10,21 @@
>>>>>>>>
>>>>>>>>      #define __HAVE_ARCH_PMD_ALLOC_ONE
>>>>>>>>      #define __HAVE_ARCH_PUD_ALLOC_ONE
>>>>>>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
>>>>>>>>      #include <asm-generic/pgalloc.h>
>>>>>>>>
>>>>>>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
>>>>>>>> +{
>>>>>>>> +       pte_t *pte;
>>>>>>>> +
>>>>>>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
>>>>>>>> +       if (!pte)
>>>>>>>> +               return NULL;
>>>>>>>> +
>>>>>>>> +       kernel_pte_init(pte);
>>>>>>>> +       return pte;
>>>>>>>> +}
>>>>>>>> +
>>>>>>>>      static inline void pmd_populate_kernel(struct mm_struct *mm,
>>>>>>>>                                            pmd_t *pmd, pte_t *pte)
>>>>>>>>      {
>>>>>>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch=
/include/asm/pgtable.h
>>>>>>>> index 9965f52ef65b..22e3a8f96213 100644
>>>>>>>> --- a/arch/loongarch/include/asm/pgtable.h
>>>>>>>> +++ b/arch/loongarch/include/asm/pgtable.h
>>>>>>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, u=
nsigned long addr, pmd_t *pmdp, pm
>>>>>>>>      extern void pgd_init(void *addr);
>>>>>>>>      extern void pud_init(void *addr);
>>>>>>>>      extern void pmd_init(void *addr);
>>>>>>>> +extern void kernel_pte_init(void *addr);
>>>>>>>>
>>>>>>>>      /*
>>>>>>>>       * Encode/decode swap entries and swap PTEs. Swap PTEs are al=
l PTEs that
>>>>>>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
>>>>>>>> index 8a87a482c8f4..9f26e933a8a3 100644
>>>>>>>> --- a/arch/loongarch/mm/init.c
>>>>>>>> +++ b/arch/loongarch/mm/init.c
>>>>>>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned l=
ong addr)
>>>>>>>>             if (!pmd_present(pmdp_get(pmd))) {
>>>>>>>>                     pte_t *pte;
>>>>>>>>
>>>>>>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>>>>>>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
>>>>>>>>                     if (!pte)
>>>>>>>>                             panic("%s: Failed to allocate memory\n=
", __func__);
>>>>>>>> +
>>>>>>>> +               kernel_pte_init(pte);
>>>>>>>>                     pmd_populate_kernel(&init_mm, pmd, pte);
>>>>>>>>             }
>>>>>>>>
>>>>>>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/ka=
san_init.c
>>>>>>>> index 427d6b1aec09..34988573b0d5 100644
>>>>>>>> --- a/arch/loongarch/mm/kasan_init.c
>>>>>>>> +++ b/arch/loongarch/mm/kasan_init.c
>>>>>>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *p=
mdp, unsigned long addr,
>>>>>>>>                     phys_addr_t page_phys =3D early ?
>>>>>>>>                                             __pa_symbol(kasan_earl=
y_shadow_page)
>>>>>>>>                                                   : kasan_alloc_ze=
roed_page(node);
>>>>>>>> +               if (!early)
>>>>>>>> +                       kernel_pte_init(__va(page_phys));
>>>>>>>>                     next =3D addr + PAGE_SIZE;
>>>>>>>>                     set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys)=
, PAGE_KERNEL));
>>>>>>>>             } while (ptep++, addr =3D next, addr !=3D end && __pte=
_none(early, ptep_get(ptep)));
>>>>>>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
>>>>>>>>                     set_pte(&kasan_early_shadow_pte[i],
>>>>>>>>                             pfn_pte(__phys_to_pfn(__pa_symbol(kasa=
n_early_shadow_page)), PAGE_KERNEL_RO));
>>>>>>>>
>>>>>>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>>>>>>>> +       kernel_pte_init(kasan_early_shadow_page);
>>>>>>>>             csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR=
_PGDH);
>>>>>>>>             local_flush_tlb_all();
>>>>>>>>
>>>>>>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtab=
le.c
>>>>>>>> index eb6a29b491a7..228ffc1db0a3 100644
>>>>>>>> --- a/arch/loongarch/mm/pgtable.c
>>>>>>>> +++ b/arch/loongarch/mm/pgtable.c
>>>>>>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>>>>>>>>      }
>>>>>>>>      EXPORT_SYMBOL_GPL(pgd_alloc);
>>>>>>>>
>>>>>>>> +void kernel_pte_init(void *addr)
>>>>>>>> +{
>>>>>>>> +       unsigned long *p, *end;
>>>>>>>> +       unsigned long entry;
>>>>>>>> +
>>>>>>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
>>>>>>>> +       p =3D (unsigned long *)addr;
>>>>>>>> +       end =3D p + PTRS_PER_PTE;
>>>>>>>> +
>>>>>>>> +       do {
>>>>>>>> +               p[0] =3D entry;
>>>>>>>> +               p[1] =3D entry;
>>>>>>>> +               p[2] =3D entry;
>>>>>>>> +               p[3] =3D entry;
>>>>>>>> +               p[4] =3D entry;
>>>>>>>> +               p +=3D 8;
>>>>>>>> +               p[-3] =3D entry;
>>>>>>>> +               p[-2] =3D entry;
>>>>>>>> +               p[-1] =3D entry;
>>>>>>>> +       } while (p !=3D end);
>>>>>>>> +}
>>>>>>>> +
>>>>>>>>      void pgd_init(void *addr)
>>>>>>>>      {
>>>>>>>>             unsigned long *p, *end;
>>>>>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>>>>>>>> index ecf63d2b0582..6909fe059a2c 100644
>>>>>>>> --- a/include/linux/mm.h
>>>>>>>> +++ b/include/linux/mm.h
>>>>>>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size=
);
>>>>>>>>      struct page * __populate_section_memmap(unsigned long pfn,
>>>>>>>>                     unsigned long nr_pages, int nid, struct vmem_a=
ltmap *altmap,
>>>>>>>>                     struct dev_pagemap *pgmap);
>>>>>>>> +void kernel_pte_init(void *addr);
>>>>>>>>      void pmd_init(void *addr);
>>>>>>>>      void pud_init(void *addr);
>>>>>>>>      pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
>>>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>>>>>> index 89895f38f722..ac607c306292 100644
>>>>>>>> --- a/mm/kasan/init.c
>>>>>>>> +++ b/mm/kasan/init.c
>>>>>>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pm=
d, unsigned long addr,
>>>>>>>>             }
>>>>>>>>      }
>>>>>>>>
>>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>>>>>> +{
>>>>>>>> +}
>>>>>>>> +
>>>>>>>>      static int __ref zero_pmd_populate(pud_t *pud, unsigned long =
addr,
>>>>>>>>                                     unsigned long end)
>>>>>>>>      {
>>>>>>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud=
, unsigned long addr,
>>>>>>>>
>>>>>>>>                             if (slab_is_available())
>>>>>>>>                                     p =3D pte_alloc_one_kernel(&in=
it_mm);
>>>>>>>> -                       else
>>>>>>>> +                       else {
>>>>>>>>                                     p =3D early_alloc(PAGE_SIZE, N=
UMA_NO_NODE);
>>>>>>>> +                               kernel_pte_init(p);
>>>>>>>> +                       }
>>>>>>>>                             if (!p)
>>>>>>>>                                     return -ENOMEM;
>>>>>>>>
>>>>>>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
>>>>>>>> index edcc7a6b0f6f..c0388b2e959d 100644
>>>>>>>> --- a/mm/sparse-vmemmap.c
>>>>>>>> +++ b/mm/sparse-vmemmap.c
>>>>>>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_z=
ero(unsigned long size, int node)
>>>>>>>>             return p;
>>>>>>>>      }
>>>>>>>>
>>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>>>>>> +{
>>>>>>>> +}
>>>>>>>> +
>>>>>>>>      pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned l=
ong addr, int node)
>>>>>>>>      {
>>>>>>>>             pmd_t *pmd =3D pmd_offset(pud, addr);
>>>>>>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *=
pud, unsigned long addr, int node)
>>>>>>>>                     void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE=
, node);
>>>>>>>>                     if (!p)
>>>>>>>>                             return NULL;
>>>>>>>> +               kernel_pte_init(p);
>>>>>>>>                     pmd_populate_kernel(&init_mm, pmd, p);
>>>>>>>>             }
>>>>>>>>             return pmd;
>>>>>>>> --
>>>>>>>> 2.39.3
>>>>>>>>
>>>>>>
>>>>>>
>>>>
>>>>
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f727e384-6989-0942-1cc8-7188f558ee39%40loongson.cn.
