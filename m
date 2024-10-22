Return-Path: <kasan-dev+bncBAABB4EE3S4AMGQEILZU7CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id E9B309A9586
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:40:01 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-6e3705b2883sf99878077b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:40:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729561200; cv=pass;
        d=google.com; s=arc-20240605;
        b=DTMJZha/TWYy9PBzyIRhe+N3uCCtJ9lzOgy4ZSRXFjGXpJXRWGKfjDa7qnDkFJSUE7
         IGOLMTiBCKzC2DR3K8y1ybDzLTKWTnLD2iKuLcSom1ldEsuJ+sylcs303Kxm0UtW7dVh
         jgP5fCn0Oem+3Wny5wupM9dD/2JOJqj6J88iKjkMMnFB10Lwly/tDAG3UpjKEx7DAtld
         pXK87hBbRWd2zor75IGp6SJjmPrjj7iPE2wv5ZOqtH0Ubcaz2DdgK5ONIoKwA2HliLZF
         k0AziO8/6rXz0RsB7QeDvAhZc4t4G8HlJxBjeGgN0yBPiQ5j7tr6hfYeDyJmKd/eim61
         vRWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=1uMcCGobRzkn0ry7VaslTps3m2o0TQcMVh2YTwaOOf8=;
        fh=eU0Pda2EB/Qp9DLV1x6v6XzFBYftmv7ZXfTDbeduiu8=;
        b=gS74iptZy8pehq6+VIAA7K0GrbQcRJphJnJBKxB2BbgwLY70RovMT/A+Wt0g/lp74n
         mIp27WOAuh7//vKtkbSfWuzothxcPAaE88AwKTTgaNLqXR0wGehvpMw+ahwAdOsPi7wL
         yFwhjSd983eqpCAWwpOWJO1PSrR9YFDvr6MXd9c3MAaOcjXpj/VQPs06U85lnszseJon
         ftTamtGfY5lhj+NdEiu0O/E6XxoC5SglETKvVHmyFwnicDnWjlaHzKzg5HCBwrgVvMbZ
         Rwj10fc9E4BQSyeMCKCVv7RvIS0Uh+2yH0U+Ldanhip2Q7esVt+sMr0u/usxo1DgKB0b
         lvSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729561200; x=1730166000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1uMcCGobRzkn0ry7VaslTps3m2o0TQcMVh2YTwaOOf8=;
        b=QN0a9KB/1pRWgL7afdyITg1GexxT71KY9tk3Q0cFAHdOVnp3X4KTo4xaiZSaYdV/Tw
         7cea+1GdPEiIp3twFF9StEYKc2knC+ST3p1jTrugf8BPlVCXaiG/5GU1mxM/t5aVbCe3
         ZjiY/4WfERpYG0m+tpksCG/NDKvVlr18ImF5DfCn0WV8LcEl3H30Nc8MPGpFiFIs2EfB
         j6yviQ43LHPTgdMxJu1ShTVRLi7dd3Ya3yX7WBD7a6fC3I5whlczRMUHaOl+kFNHLFdm
         WKlaJGUxTefstOs9opRLJnWnwd8lUxL2hjnQ40WB9NUqtf/ThR7q/7Wu1riOAHLcaNpQ
         kqVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729561200; x=1730166000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1uMcCGobRzkn0ry7VaslTps3m2o0TQcMVh2YTwaOOf8=;
        b=hNTTj4HCYMtpZmvjq9nCpjKoUHpJhUUyVOMxhP9zNTQhH3ObK8eGOfLdIZP4OOHsQW
         cSFlmtrmndMfJ+1NlRG8wKfvq0X9GzZvtLCFYNXbr0f8P01O0YoCiRHC1HM1kUhV8WyZ
         x/4R9i/97PbNLSdd5uSl5Nv4i9JtB0yfCkEo8vwRN8dObgRKZNlSmqYksR5VzDtIlge5
         8KMppXopewXXI2qTZ0QNdjMsf8qfSQrDAGnxycFx+gMzFmERS6yEJML+mBxe4n+VAp5/
         7DbngBz2auaojtc0NI+iGQOS+B8WD/1sOxrDN/hgnH/1NtlVHlKNoPfe2Bp3DsoW6hN+
         7ZkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKFtd2KpC1KsoSRmYOeSntOec819/22mpGPd0G9Lq/AD7S0L1NKnAY85VYcrLVXoPJUUAzGA==@lfdr.de
X-Gm-Message-State: AOJu0Yxl7rLWGKbWWBq9eeDOpIrTH+GTGw5wWjxb7Qlh9ybOvYb3+ZV1
	zp3NxVN7cdvRZ+rChBoMR0GEVbWGpsRivAGfp0qcqGGqcZoqPVDV
X-Google-Smtp-Source: AGHT+IGi5Cssk+hT7V6ke+6tWdkhZMJXSlgtunwEowbutpoGJ0a0GUpmW93+JIQZzital6KZ6afizQ==
X-Received: by 2002:a05:6902:1b0c:b0:e26:2aa0:a3b0 with SMTP id 3f1490d57ef6-e2bb168d87bmr10000701276.45.1729561200372;
        Mon, 21 Oct 2024 18:40:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5954:0:b0:458:a6c:8071 with SMTP id d75a77b69052e-4609b6b5e82ls101101041cf.1.-pod-prod-04-us;
 Mon, 21 Oct 2024 18:39:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUatguFriNbuZLJC587C/3OusKS+kl5I1xjhkkr05LZfEN1SYrxw7tWvZ1W+Cpr3QV3Q2xRklvGld0=@googlegroups.com
X-Received: by 2002:a05:622a:4e0b:b0:458:571c:f9cc with SMTP id d75a77b69052e-460aedfa234mr188185471cf.46.1729561199720;
        Mon, 21 Oct 2024 18:39:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729561199; cv=none;
        d=google.com; s=arc-20240605;
        b=GRWIKU39i2nJ/nMm7r4EcojPSGkxbIXwvr6lDhjdoP0QzH+Jwr1PpaQTJ7+QmZqFAf
         2oC3dg2hzHuv1IqUL/DAPFBER//jcLbIQ0NLS6RHobbmc+O+51bfCPMO3z+LKD4sjMhr
         gtK3iMhtkNpFXRhWMduXv+i8PNMnrfhX8PYg/9xtdSqBsJmDtBGgqLPSsxGXRy+5CAtf
         CHoZBD9A2kw8gs4TM9lZ3P1DuR1pIweIwompKBMW+eTBZ3zWd7Vn0agcHQf8QwjR+XFq
         +QZQUSPNcrrr+iZq7IXObof5wyHRihuuTa2GD7F8AczTaNyCN6EGi8tw8045XROROlU9
         VouA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=gfjZOl8PCEQxj7XbVfhX8v2wUDQqj3NGkMyUJ6E2YgQ=;
        fh=GN+TnQBjgabBq5rNIUtQQucUASmSQHUB4i4c84RJIVo=;
        b=ZStq+zXE9HN3f519QZgFpS15DDJyCfYrFfJ1WBdroucrndpP1hbzfiK8RCRF+JQGD/
         hIOwSe18Ax2Q13o4CmuMjZG9/4MPZQK1r3J2uOglE/5V42KpW4D4xhmub7KIKOl6PE/d
         9NQwwX0AWDwjOcsrHkQLkrzsQskqqTJ43HXb3t7iM3cxZgqlhl1aTWlOQmUtgi4au5fA
         feTmIj9tcH9GYLeRCdudP7Pjew3DcRbsufgkBl3M4UOYewMj51ks41JZ+t7+dSHtN4Oc
         kVw2hsMsu7mik1B7RLyx03v4cqo2F02uLpKj1X/PlSBoxYns7Q1TisecLBT9EVPXoHYK
         R/gA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d75a77b69052e-460d3db85adsi2154141cf.4.2024.10.21.18.39.58
        for <kasan-dev@googlegroups.com>;
        Mon, 21 Oct 2024 18:39:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.20.42.62])
	by gateway (Coremail) with SMTP id _____8AxLOJpAhdnS9IDAA--.9020S3;
	Tue, 22 Oct 2024 09:39:54 +0800 (CST)
Received: from [10.20.42.62] (unknown [10.20.42.62])
	by front1 (Coremail) with SMTP id qMiowMCxS+BlAhdnJ+gFAA--.35170S3;
	Tue, 22 Oct 2024 09:39:52 +0800 (CST)
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
 <f727e384-6989-0942-1cc8-7188f558ee39@loongson.cn>
 <CAAhV-H5CADad2EGv0zMQrgrvpNRtBTWDoXFj=j+zXEJdy7HkAQ@mail.gmail.com>
From: maobibo <maobibo@loongson.cn>
Message-ID: <33d6cb6b-834b-f9b8-df28-b15243994f9b@loongson.cn>
Date: Tue, 22 Oct 2024 09:39:27 +0800
User-Agent: Mozilla/5.0 (X11; Linux loongarch64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CAAhV-H5CADad2EGv0zMQrgrvpNRtBTWDoXFj=j+zXEJdy7HkAQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: qMiowMCxS+BlAhdnJ+gFAA--.35170S3
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBj9fXoW3KF1kGFW8CryDtFykJFW7KFX_yoW8AF1rCo
	W5Jr47tr18Jr1UJr10y34Dtw1UJw1Dtw4UJrWUAr4UJF1Ut34UJr1UJr15XFW7Gr1rJr47
	JryUXr4DZry7Jrn8l-sFpf9Il3svdjkaLaAFLSUrUUUUeb8apTn2vfkv8UJUUUU8wcxFpf
	9Il3svdxBIdaVrn0xqx4xG64xvF2IEw4CE5I8CrVC2j2Jv73VFW2AGmfu7bjvjm3AaLaJ3
	UjIYCTnIWjp_UUUO17kC6x804xWl14x267AKxVWUJVW8JwAFc2x0x2IEx4CE42xK8VAvwI
	8IcIk0rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2ocxC64kIII0Yj41l84x0c7CEw4AK67xG
	Y2AK021l84ACjcxK6xIIjxv20xvE14v26ryj6F1UM28EF7xvwVC0I7IYx2IY6xkF7I0E14
	v26r4j6F4UM28EF7xvwVC2z280aVAFwI0_Gr0_Cr1l84ACjcxK6I8E87Iv6xkF7I0E14v2
	6r4j6r4UJwAaw2AFwI0_JF0_Jw1le2I262IYc4CY6c8Ij28IcVAaY2xG8wAqjxCEc2xF0c
	Ia020Ex4CE44I27wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcVAFwI0_JF0_
	Jw1lYx0Ex4A2jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG0xvEwIxGrw
	CYjI0SjxkI62AI1cAE67vIY487MxkF7I0En4kS14v26r126r1DMxAIw28IcxkI7VAKI48J
	MxC20s026xCaFVCjc4AY6r1j6r4UMxCIbckI1I0E14v26r126r1DMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	WUJVW8JwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Gr0_Cr1l
	IxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU8SzutUUUU
	U==
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



On 2024/10/21 =E4=B8=8B=E5=8D=886:13, Huacai Chen wrote:
> On Mon, Oct 21, 2024 at 9:23=E2=80=AFAM maobibo <maobibo@loongson.cn> wro=
te:
>>
>>
>>
>> On 2024/10/18 =E4=B8=8B=E5=8D=882:32, Huacai Chen wrote:
>>> On Fri, Oct 18, 2024 at 2:23=E2=80=AFPM maobibo <maobibo@loongson.cn> w=
rote:
>>>>
>>>>
>>>>
>>>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:23, Huacai Chen wrote:
>>>>> On Fri, Oct 18, 2024 at 12:16=E2=80=AFPM maobibo <maobibo@loongson.cn=
> wrote:
>>>>>>
>>>>>>
>>>>>>
>>>>>> On 2024/10/18 =E4=B8=8B=E5=8D=8812:11, Huacai Chen wrote:
>>>>>>> On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.=
cn> wrote:
>>>>>>>>
>>>>>>>>
>>>>>>>>
>>>>>>>> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
>>>>>>>>> Hi, Bibo,
>>>>>>>>>
>>>>>>>>> I applied this patch but drop the part of arch/loongarch/mm/kasan=
_init.c:
>>>>>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-=
loongson.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced5=
0afc403067
>>>>>>>>>
>>>>>>>>> Because kernel_pte_init() should operate on page-table pages, not=
 on
>>>>>>>>> data pages. You have already handle page-table page in
>>>>>>>>> mm/kasan/init.c, and if we don't drop the modification on data pa=
ges
>>>>>>>>> in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KAS=
AN is
>>>>>>>>> enabled.
>>>>>>>>>
>>>>>>>> static inline void set_pte(pte_t *ptep, pte_t pteval)
>>>>>>>>       {
>>>>>>>>             WRITE_ONCE(*ptep, pteval);
>>>>>>>> -
>>>>>>>> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
>>>>>>>> -               pte_t *buddy =3D ptep_buddy(ptep);
>>>>>>>> -               /*
>>>>>>>> -                * Make sure the buddy is global too (if it's !non=
e,
>>>>>>>> -                * it better already be global)
>>>>>>>> -                */
>>>>>>>> -               if (pte_none(ptep_get(buddy))) {
>>>>>>>> -#ifdef CONFIG_SMP
>>>>>>>> -                       /*
>>>>>>>> -                        * For SMP, multiple CPUs can race, so we =
need
>>>>>>>> -                        * to do this atomically.
>>>>>>>> -                        */
>>>>>>>> -                       __asm__ __volatile__(
>>>>>>>> -                       __AMOR "$zero, %[global], %[buddy] \n"
>>>>>>>> -                       : [buddy] "+ZB" (buddy->pte)
>>>>>>>> -                       : [global] "r" (_PAGE_GLOBAL)
>>>>>>>> -                       : "memory");
>>>>>>>> -
>>>>>>>> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>>>>>>>> -#else /* !CONFIG_SMP */
>>>>>>>> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(=
buddy)) | _PAGE_GLOBAL));
>>>>>>>> -#endif /* CONFIG_SMP */
>>>>>>>> -               }
>>>>>>>> -       }
>>>>>>>> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>>>>>>>>       }
>>>>>>>>
>>>>>>>> No, please hold on. This issue exists about twenty years, Do we ne=
ed be
>>>>>>>> in such a hurry now?
>>>>>>>>
>>>>>>>> why is DBAR(0b11000) added in set_pte()?
>>>>>>> It exists before, not added by this patch. The reason is explained =
in
>>>>>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/=
commit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
>>>>>> why speculative accesses may cause spurious page fault in kernel spa=
ce
>>>>>> with PTE enabled?  speculative accesses exists anywhere, it does not
>>>>>> cause spurious page fault.
>>>>> Confirmed by Ruiyang Wu, and even if DBAR(0b11000) is wrong, that
>>>>> means another patch's mistake, not this one. This one just keeps the
>>>>> old behavior.
>>>>> +CC Ruiyang Wu here.
>>>> Also from Ruiyang Wu, the information is that speculative accesses may
>>>> insert stale TLB, however no page fault exception.
>>>>
>>>> So adding barrier in set_pte() does not prevent speculative accesses.
>>>> And you write patch here, however do not know the actual reason?
>>>>
>>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/com=
mit/?h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030
>>> I have CCed Ruiyang, whether the description is correct can be judged b=
y him.
>>
>> There are some problems to add barrier() in set_pte():
>>
>> 1. There is such issue only for HW ptw enabled and kernel address space,
>> is that? Also it may be two heavy to add barrier in set_pte(), comparing
>> to do this in flush_cache_vmap().
> So adding a barrier in set_pte() may not be the best solution for
> performance, but you cannot say it is a wrong solution. And yes, we
> can only care the kernel space, which is also the old behavior before
> this patch, so set_pte() should be:
>=20
> static inline void set_pte(pte_t *ptep, pte_t pteval)
> {
>          WRITE_ONCE(*ptep, pteval);
> #ifdef CONFIG_SMP
>          if (pte_val(pteval) & _PAGE_GLOBAL)
cpu_has_ptw seems also need here, if it is only for hw page walk.
>                  DBAR(0b11000); /* o_wrw =3D 0b11000 */
> #endif
> }
>=20
> Putting a dbar unconditionally in set_pte() is my mistake, I'm sorry for =
 that.
>=20
>>
>> 2. LoongArch is different with other other architectures, two pages are
>> included in one TLB entry. If there is two consecutive page mapped and
>> memory access, there will page fault for the second memory access. Such
>> as:
>>      addr1 =3Dpercpu_alloc(pagesize);
>>      val1 =3D *(int *)addr1;
>>        // With page table walk, addr1 is present and addr2 is pte_none
>>        // TLB entry includes valid pte for addr1, invalid pte for addr2
>>      addr2 =3Dpercpu_alloc(pagesize); // will not flush tlb in first tim=
e
>>      val2 =3D *(int *)addr2;
>>        // With page table walk, addr1 is present and addr2 is present al=
so
>>        // TLB entry includes valid pte for addr1, invalid pte for addr2
>>      So there will be page fault when accessing address addr2
>>
>> There there is the same problem with user address space. By the way,
>> there is HW prefetching technology, negative effective of HW prefetching
>> technology will be tlb added. So there is potential page fault if memory
>> is allocated and accessed in the first time.
> As discussed internally, there may be three problems related to
> speculative access in detail: 1) a load/store after set_pte() is
> prioritized before, which can be prevented by dbar, 2) a instruction
> fetch after set_pte() is prioritized before, which can be prevented by
> ibar, 3) the buddy tlb problem you described here, if I understand
> Ruiyang's explanation correctly this can only be prevented by the
> filter in do_page_fault().
>=20
>  From experiments, without the patch "LoongArch: Improve hardware page
> table walker", there are about 80 times of spurious page faults during
> boot, and increases continually during stress tests. And after that
> patch which adds a dbar to set_pte(), we cannot observe spurious page
> faults anymore. Of course this doesn't mean 2) and 3) don't exist, but
Good experiment result. Could you share me code about page fault=20
counting and test cases?

> we can at least say 1) is the main case. On this basis, in "LoongArch:
> Improve hardware page table walker" we use a relatively cheap dbar
> (compared to ibar) to prevent the main case, and add a filter to
> handle 2) and 3). Such a solution is reasonable.
>=20
>=20
>>
>> 3. For speculative execution, if it is user address, there is eret from
>> syscall. eret will rollback all speculative execution instruction. So it
>> is only problem for speculative execution. And how to verify whether it
>> is the problem of speculative execution or it is the problem of clause 2=
?
> As described above, if spurious page faults still exist after adding
> dbar to set_pte(), it may be a problem of clause 2 (case 3 in my
> description), otherwise it is not a problem of clause 2.
>=20
> At last, this patch itself is attempting to solve the concurrent
> problem about _PAGE_GLOBAL, so adding pte_alloc_one_kernel() and
> removing the buddy stuff in set_pte() are what it needs. However it
> shouldn't touch the logic of dbar in set_pte(), whether "LoongArch:
> Improve hardware page table walker" is right or wrong.
yes, I agree. We can discuss set_pte() issue in later. Simple for this=20
patch to solve concurrent problem, it is ok
https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongson.g=
it/diff/mm/kasan/init.c?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70c=
ed50afc403067

Regards
Bibo Mao
>=20
>=20
> Huacai
>=20
>>
>> Regards
>> Bibo Mao
>>
>>
>>>
>>> Huacai
>>>
>>>>
>>>> Bibo Mao
>>>>>
>>>>> Huacai
>>>>>
>>>>>>
>>>>>> Obvious you do not it and you write wrong patch.
>>>>>>
>>>>>>>
>>>>>>> Huacai
>>>>>>>
>>>>>>>>
>>>>>>>> Regards
>>>>>>>> Bibo Mao
>>>>>>>>> Huacai
>>>>>>>>>
>>>>>>>>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongs=
on.cn> wrote:
>>>>>>>>>>
>>>>>>>>>> Unlike general architectures, there are two pages in one TLB ent=
ry
>>>>>>>>>> on LoongArch system. For kernel space, it requires both two pte
>>>>>>>>>> entries with PAGE_GLOBAL bit set, else HW treats it as non-globa=
l
>>>>>>>>>> tlb, there will be potential problems if tlb entry for kernel sp=
ace
>>>>>>>>>> is not global. Such as fail to flush kernel tlb with function
>>>>>>>>>> local_flush_tlb_kernel_range() which only flush tlb with global =
bit.
>>>>>>>>>>
>>>>>>>>>> With function kernel_pte_init() added, it can be used to init pt=
e
>>>>>>>>>> table when it is created for kernel address space, and the defau=
lt
>>>>>>>>>> initial pte value is PAGE_GLOBAL rather than zero at beginning.
>>>>>>>>>>
>>>>>>>>>> Kernel address space areas includes fixmap, percpu, vmalloc, kas=
an
>>>>>>>>>> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
>>>>>>>>>>
>>>>>>>>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
>>>>>>>>>> ---
>>>>>>>>>>       arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>>>>>>>>>>       arch/loongarch/include/asm/pgtable.h |  1 +
>>>>>>>>>>       arch/loongarch/mm/init.c             |  4 +++-
>>>>>>>>>>       arch/loongarch/mm/kasan_init.c       |  4 +++-
>>>>>>>>>>       arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++=
++++++
>>>>>>>>>>       include/linux/mm.h                   |  1 +
>>>>>>>>>>       mm/kasan/init.c                      |  8 +++++++-
>>>>>>>>>>       mm/sparse-vmemmap.c                  |  5 +++++
>>>>>>>>>>       8 files changed, 55 insertions(+), 3 deletions(-)
>>>>>>>>>>
>>>>>>>>>> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongar=
ch/include/asm/pgalloc.h
>>>>>>>>>> index 4e2d6b7ca2ee..b2698c03dc2c 100644
>>>>>>>>>> --- a/arch/loongarch/include/asm/pgalloc.h
>>>>>>>>>> +++ b/arch/loongarch/include/asm/pgalloc.h
>>>>>>>>>> @@ -10,8 +10,21 @@
>>>>>>>>>>
>>>>>>>>>>       #define __HAVE_ARCH_PMD_ALLOC_ONE
>>>>>>>>>>       #define __HAVE_ARCH_PUD_ALLOC_ONE
>>>>>>>>>> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
>>>>>>>>>>       #include <asm-generic/pgalloc.h>
>>>>>>>>>>
>>>>>>>>>> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
>>>>>>>>>> +{
>>>>>>>>>> +       pte_t *pte;
>>>>>>>>>> +
>>>>>>>>>> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
>>>>>>>>>> +       if (!pte)
>>>>>>>>>> +               return NULL;
>>>>>>>>>> +
>>>>>>>>>> +       kernel_pte_init(pte);
>>>>>>>>>> +       return pte;
>>>>>>>>>> +}
>>>>>>>>>> +
>>>>>>>>>>       static inline void pmd_populate_kernel(struct mm_struct *m=
m,
>>>>>>>>>>                                             pmd_t *pmd, pte_t *p=
te)
>>>>>>>>>>       {
>>>>>>>>>> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongar=
ch/include/asm/pgtable.h
>>>>>>>>>> index 9965f52ef65b..22e3a8f96213 100644
>>>>>>>>>> --- a/arch/loongarch/include/asm/pgtable.h
>>>>>>>>>> +++ b/arch/loongarch/include/asm/pgtable.h
>>>>>>>>>> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm,=
 unsigned long addr, pmd_t *pmdp, pm
>>>>>>>>>>       extern void pgd_init(void *addr);
>>>>>>>>>>       extern void pud_init(void *addr);
>>>>>>>>>>       extern void pmd_init(void *addr);
>>>>>>>>>> +extern void kernel_pte_init(void *addr);
>>>>>>>>>>
>>>>>>>>>>       /*
>>>>>>>>>>        * Encode/decode swap entries and swap PTEs. Swap PTEs are=
 all PTEs that
>>>>>>>>>> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
>>>>>>>>>> index 8a87a482c8f4..9f26e933a8a3 100644
>>>>>>>>>> --- a/arch/loongarch/mm/init.c
>>>>>>>>>> +++ b/arch/loongarch/mm/init.c
>>>>>>>>>> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned=
 long addr)
>>>>>>>>>>              if (!pmd_present(pmdp_get(pmd))) {
>>>>>>>>>>                      pte_t *pte;
>>>>>>>>>>
>>>>>>>>>> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
>>>>>>>>>> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE)=
;
>>>>>>>>>>                      if (!pte)
>>>>>>>>>>                              panic("%s: Failed to allocate memor=
y\n", __func__);
>>>>>>>>>> +
>>>>>>>>>> +               kernel_pte_init(pte);
>>>>>>>>>>                      pmd_populate_kernel(&init_mm, pmd, pte);
>>>>>>>>>>              }
>>>>>>>>>>
>>>>>>>>>> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/=
kasan_init.c
>>>>>>>>>> index 427d6b1aec09..34988573b0d5 100644
>>>>>>>>>> --- a/arch/loongarch/mm/kasan_init.c
>>>>>>>>>> +++ b/arch/loongarch/mm/kasan_init.c
>>>>>>>>>> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t =
*pmdp, unsigned long addr,
>>>>>>>>>>                      phys_addr_t page_phys =3D early ?
>>>>>>>>>>                                              __pa_symbol(kasan_e=
arly_shadow_page)
>>>>>>>>>>                                                    : kasan_alloc=
_zeroed_page(node);
>>>>>>>>>> +               if (!early)
>>>>>>>>>> +                       kernel_pte_init(__va(page_phys));
>>>>>>>>>>                      next =3D addr + PAGE_SIZE;
>>>>>>>>>>                      set_pte(ptep, pfn_pte(__phys_to_pfn(page_ph=
ys), PAGE_KERNEL));
>>>>>>>>>>              } while (ptep++, addr =3D next, addr !=3D end && __=
pte_none(early, ptep_get(ptep)));
>>>>>>>>>> @@ -287,7 +289,7 @@ void __init kasan_init(void)
>>>>>>>>>>                      set_pte(&kasan_early_shadow_pte[i],
>>>>>>>>>>                              pfn_pte(__phys_to_pfn(__pa_symbol(k=
asan_early_shadow_page)), PAGE_KERNEL_RO));
>>>>>>>>>>
>>>>>>>>>> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>>>>>>>>>> +       kernel_pte_init(kasan_early_shadow_page);
>>>>>>>>>>              csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_=
CSR_PGDH);
>>>>>>>>>>              local_flush_tlb_all();
>>>>>>>>>>
>>>>>>>>>> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgt=
able.c
>>>>>>>>>> index eb6a29b491a7..228ffc1db0a3 100644
>>>>>>>>>> --- a/arch/loongarch/mm/pgtable.c
>>>>>>>>>> +++ b/arch/loongarch/mm/pgtable.c
>>>>>>>>>> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>>>>>>>>>>       }
>>>>>>>>>>       EXPORT_SYMBOL_GPL(pgd_alloc);
>>>>>>>>>>
>>>>>>>>>> +void kernel_pte_init(void *addr)
>>>>>>>>>> +{
>>>>>>>>>> +       unsigned long *p, *end;
>>>>>>>>>> +       unsigned long entry;
>>>>>>>>>> +
>>>>>>>>>> +       entry =3D (unsigned long)_PAGE_GLOBAL;
>>>>>>>>>> +       p =3D (unsigned long *)addr;
>>>>>>>>>> +       end =3D p + PTRS_PER_PTE;
>>>>>>>>>> +
>>>>>>>>>> +       do {
>>>>>>>>>> +               p[0] =3D entry;
>>>>>>>>>> +               p[1] =3D entry;
>>>>>>>>>> +               p[2] =3D entry;
>>>>>>>>>> +               p[3] =3D entry;
>>>>>>>>>> +               p[4] =3D entry;
>>>>>>>>>> +               p +=3D 8;
>>>>>>>>>> +               p[-3] =3D entry;
>>>>>>>>>> +               p[-2] =3D entry;
>>>>>>>>>> +               p[-1] =3D entry;
>>>>>>>>>> +       } while (p !=3D end);
>>>>>>>>>> +}
>>>>>>>>>> +
>>>>>>>>>>       void pgd_init(void *addr)
>>>>>>>>>>       {
>>>>>>>>>>              unsigned long *p, *end;
>>>>>>>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>>>>>>>>>> index ecf63d2b0582..6909fe059a2c 100644
>>>>>>>>>> --- a/include/linux/mm.h
>>>>>>>>>> +++ b/include/linux/mm.h
>>>>>>>>>> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long si=
ze);
>>>>>>>>>>       struct page * __populate_section_memmap(unsigned long pfn,
>>>>>>>>>>                      unsigned long nr_pages, int nid, struct vme=
m_altmap *altmap,
>>>>>>>>>>                      struct dev_pagemap *pgmap);
>>>>>>>>>> +void kernel_pte_init(void *addr);
>>>>>>>>>>       void pmd_init(void *addr);
>>>>>>>>>>       void pud_init(void *addr);
>>>>>>>>>>       pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
>>>>>>>>>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>>>>>>>>>> index 89895f38f722..ac607c306292 100644
>>>>>>>>>> --- a/mm/kasan/init.c
>>>>>>>>>> +++ b/mm/kasan/init.c
>>>>>>>>>> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *=
pmd, unsigned long addr,
>>>>>>>>>>              }
>>>>>>>>>>       }
>>>>>>>>>>
>>>>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>>>>>>>> +{
>>>>>>>>>> +}
>>>>>>>>>> +
>>>>>>>>>>       static int __ref zero_pmd_populate(pud_t *pud, unsigned lo=
ng addr,
>>>>>>>>>>                                      unsigned long end)
>>>>>>>>>>       {
>>>>>>>>>> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *p=
ud, unsigned long addr,
>>>>>>>>>>
>>>>>>>>>>                              if (slab_is_available())
>>>>>>>>>>                                      p =3D pte_alloc_one_kernel(=
&init_mm);
>>>>>>>>>> -                       else
>>>>>>>>>> +                       else {
>>>>>>>>>>                                      p =3D early_alloc(PAGE_SIZE=
, NUMA_NO_NODE);
>>>>>>>>>> +                               kernel_pte_init(p);
>>>>>>>>>> +                       }
>>>>>>>>>>                              if (!p)
>>>>>>>>>>                                      return -ENOMEM;
>>>>>>>>>>
>>>>>>>>>> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
>>>>>>>>>> index edcc7a6b0f6f..c0388b2e959d 100644
>>>>>>>>>> --- a/mm/sparse-vmemmap.c
>>>>>>>>>> +++ b/mm/sparse-vmemmap.c
>>>>>>>>>> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block=
_zero(unsigned long size, int node)
>>>>>>>>>>              return p;
>>>>>>>>>>       }
>>>>>>>>>>
>>>>>>>>>> +void __weak __meminit kernel_pte_init(void *addr)
>>>>>>>>>> +{
>>>>>>>>>> +}
>>>>>>>>>> +
>>>>>>>>>>       pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigne=
d long addr, int node)
>>>>>>>>>>       {
>>>>>>>>>>              pmd_t *pmd =3D pmd_offset(pud, addr);
>>>>>>>>>> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t=
 *pud, unsigned long addr, int node)
>>>>>>>>>>                      void *p =3D vmemmap_alloc_block_zero(PAGE_S=
IZE, node);
>>>>>>>>>>                      if (!p)
>>>>>>>>>>                              return NULL;
>>>>>>>>>> +               kernel_pte_init(p);
>>>>>>>>>>                      pmd_populate_kernel(&init_mm, pmd, p);
>>>>>>>>>>              }
>>>>>>>>>>              return pmd;
>>>>>>>>>> --
>>>>>>>>>> 2.39.3
>>>>>>>>>>
>>>>>>>>
>>>>>>>>
>>>>>>
>>>>>>
>>>>
>>>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/33d6cb6b-834b-f9b8-df28-b15243994f9b%40loongson.cn.
