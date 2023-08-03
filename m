Return-Path: <kasan-dev+bncBAABB4N7VWTAMGQEU7RA5PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 70D4E76E26D
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Aug 2023 10:06:11 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-7908cca2c06sf55040239f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Aug 2023 01:06:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691049970; cv=pass;
        d=google.com; s=arc-20160816;
        b=S++iplPpGlxCvBieeBEr385I7dxxsT2Aq73lwiUtnF6llTBAmJZVjn80EQ18GJrMv6
         /SBqgjLhPMERO4NkFPCGVOn2CbELEG/j1AMciHRp/5KP+fT8aJSTRn2RAw3eWPy7Uc2h
         /4vjNdb2qh9DAXjCr4GJHZ3nFeZw8V38AdI/zH72hqLmy0kloEyYeBeJB6kwej+TwWmE
         iX7/MPSt4Y8W9ct76lgVSVP8hVa3cgBxDfsxztINeygEu6KpH0BA42hqxypq7C5Ghwda
         NHsxJ3Vut1IqUhWy0PS7bUNctmFw2kOGodXeGUixhCbNP2hee4eHO8WxzS9jGcshdqhY
         vPUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=1N1KWROcmshLkpkjGd7PYbjohSDd21eTFZlUD2KJGwQ=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=lg0u3hFWizTjbDJcSnAJCFq7CKVJI25MvPosEVHlO8wSN2vUdWuLWKDZc6KiLLVoVC
         xDp1UmPKuca53VGNVIl+VBwn5mZDAq05lGd4gWxw7E3EtWbExIV/vWDUl+fpmQHwMODE
         Jivn7wUSogiHMvQJ1eZ5zbm/9gPxhkBomKujotIVEwzXRSrG8lpmXTvKmOT9wdCjrDeu
         E6neNdqAzgVVnKiJi8e+2ywE6UZAYHRT0P0Ze1RVkuwTYfGd0WyK3eSR/EKIOO4z25N2
         LOcWAVHFSPlSLqAeAIM0L7gwEZ4dKYlQkP0IzUUfEJzOxDwhP3z5iTIpdB6jng5/Jbzu
         TaVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691049970; x=1691654770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1N1KWROcmshLkpkjGd7PYbjohSDd21eTFZlUD2KJGwQ=;
        b=rNLTOm5lVMgYzogk5AIKY93WIenUHvoG06HAum4LImkpxBMxp8SwtTrhDzEg37R95U
         kvroLyioBNIKpEktbN5E53vxWgQe5HB9jnyS3hXgYFrFmFZmm6WQGxBAubDnK1ZNRV0p
         uB8M44NE1xuXNNEcoMqRMRUZ0NqkoOSyfqf4uaVae7Z2fYjeo6WiqXWGjTRd2idFm68v
         sDvE8w8lcwPpzi/LgvRHaUwRQPd72b0fFeNbh8fzAKtpiCCnrjsWSmHOTcG3e9JhTEVW
         D3FuYBYfVCLQp2q2bXLsp3yLi+R/FdTQuhaWPDWIzZ0lVMAT9d1iUlEwHfrES/LvVUA+
         oAGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691049970; x=1691654770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1N1KWROcmshLkpkjGd7PYbjohSDd21eTFZlUD2KJGwQ=;
        b=UW1J2Z/RRdOEzHhJhJ8616873pKjdtphpr7b9N+Tnd6U8kEA0tkpNaNEtgDwg+NySv
         SS7lAMR2z7dw2I1wGbakS0fnSxpeazl9mplKJ6lrB0Hr4+47NuPW9XWgSTJjk+mLQSx4
         iIavkOtb6+6TJQcb6dAk/kGtvOPXASIES/80Jukb8kuKPZ7diy1+9LcoTnBJa/ANNTIR
         GNWggDaWr5N3xzaoI5h07A81pyOTkVNu92tIHpkvV7LxGfaG2OFJBxgD8wYwwSCbE2Qx
         CTJItHT3IKBH4cutkzC+sDO9/XBeWVjhMqnf+EqdlvpxzYzgQ8JmBGp88K50a2QkYV7g
         JOGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaHL3aOmerE/g7oxVzT4cctmfjQoa1x+GRHF9TZKfvFe+gmf3O8
	yuH5Vc/JK2dzO/DWgq65PV4=
X-Google-Smtp-Source: APBJJlGA3Kx9GL9ETTf/xOY7aIq4SvUGGFHhyY7vo3HNnGVV+9/sivrbYlnyelBTTOcMBSHYOGJnJg==
X-Received: by 2002:a05:6e02:1142:b0:348:b114:a3d2 with SMTP id o2-20020a056e02114200b00348b114a3d2mr14405782ill.21.1691049969851;
        Thu, 03 Aug 2023 01:06:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5213:0:b0:33b:7f21:7d7e with SMTP id g19-20020a925213000000b0033b7f217d7els4962935ilb.0.-pod-prod-09-us;
 Thu, 03 Aug 2023 01:06:09 -0700 (PDT)
X-Received: by 2002:a05:6e02:170d:b0:346:24c2:4f87 with SMTP id u13-20020a056e02170d00b0034624c24f87mr19601703ill.32.1691049969153;
        Thu, 03 Aug 2023 01:06:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691049969; cv=none;
        d=google.com; s=arc-20160816;
        b=PT0crQJkwmNW3VG/nwPTe5enK05oZp1OzWBsAosQ0MxBQt951BxQ4h07BpueW0My+u
         E63gMpaWEpBeS43ps9wgnf0Va0VY9KWEiVtVD+TFnTHWtoLbReJEDxxO4xIh9Qlme29u
         ibItzn94wVuP1QfwIJ03U9Opt47j+feDtLX5BEskTVcvUWvpflcApJFNeJ32M8xc8Ca8
         qJcrX0Xyqljj0UALJkovfRNQmCtR/735Gfsk/0MMPD4TWE+GIb3eIVXC4QL/S+XThTBF
         QUcF2sWhbG6vXjRzZFce1OKZAP18iziL3uONDknXPOCCAkWSSVBX0PHjBWs8JriSBk0l
         lmWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from;
        bh=MK5LYRbFtsUe3oM/I42XrNz9zfKU6z9T17StV29UIes=;
        fh=PtPKd2tcWuVtu+yL18J6sFXYyO2PPLg/Xbo07e2JVhk=;
        b=KQoUe5lu8NgjK+hKOXJBIS4B0nS7sh8aJXi4m2J5IaaH+4ti+UksgSMRSPed3WlrMo
         UudIo3tzKLSRaDbpkhiqaJbOfsCNShhe4ncjtvWIX3oBen7wj0ifRRqE5aiTNMwlO05N
         1UFPN0aQmRzdPlLnLbFpyvyfjMsE+J+SM+vIZSygFg1r2hZNeKXWP44FdrTPisVSZ4WB
         5AJpCNlXR1ABs3mg/fGIN7ygl2HqUgdZsP5y4jbmRnlXga1ne8EhoL6kAi922XsMxG/A
         ccTBVqRVZ5I2TpQs+h74n5Ccd9hgHX/UE7Gx9Mgde+S7qgIdDgsG73G9muyyS3VaZMEh
         TKCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id y2-20020a023542000000b00429649d963fsi662875jae.6.2023.08.03.01.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Aug 2023 01:06:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 31d6717c58ef4209b175782d51f77270-20230803
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:6068e0c5-4592-4c2a-864d-cdc44bfed288,IP:25,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:10
X-CID-INFO: VERSION:1.1.28,REQID:6068e0c5-4592-4c2a-864d-cdc44bfed288,IP:25,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:10
X-CID-META: VersionHash:176cd25,CLOUDID:2f581ab4-a467-4aa9-9e04-f584452e3794,B
	ulkID:230802231252IHNI1SQW,BulkQuantity:1,Recheck:0,SF:19|44|24|17|102,TC:
	nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:40,QS:nil,BEC:nil,COL:0,OSI
	:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,
	TF_CID_SPAM_ULS
X-UUID: 31d6717c58ef4209b175782d51f77270-20230803
Received: from ubuntu [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 166434915; Thu, 03 Aug 2023 16:05:58 +0800
From: Enze Li <lienze@kylinos.cn>
To: Huacai Chen <chenhuacai@kernel.org>
Cc: kernel@xen0n.name,  loongarch@lists.linux.dev,  glider@google.com,
  elver@google.com,  akpm@linux-foundation.org,
  kasan-dev@googlegroups.com,  linux-mm@kvack.org,  zhangqing@loongson.cn,
  yangtiezhu@loongson.cn,  dvyukov@google.com
Subject: Re: [PATCH 0/4 v3] Add KFENCE support for LoongArch
In-Reply-To: <CAAhV-H6FqreZtuOXYayhu=bLZeij+fxygbK5Mpw_kVuPTvdbWw@mail.gmail.com>
	(Huacai Chen's message of "Wed, 2 Aug 2023 23:12:23 +0800")
References: <20230801025815.2436293-1-lienze@kylinos.cn>
	<CAAhV-H6FqreZtuOXYayhu=bLZeij+fxygbK5Mpw_kVuPTvdbWw@mail.gmail.com>
Date: Thu, 03 Aug 2023 16:05:45 +0800
Message-ID: <87a5v83606.fsf@kylinos.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

On Wed, Aug 02 2023 at 11:12:23 PM +0800, Huacai Chen wrote:

> Hi, Enze,
>
> I applied this series (with some small modifications) together with KASAN=
 at:
> https://github.com/chenhuacai/linux/commits/loongarch-next
>
> Please confirm everything works well for you.

Hi Huacai,

Thanks for your patience these days.

I've tested this on both a physical machine and a qemu VM.  It works
well.

BTW, if there're any modifications, bugs or improvments to KFENCE on
LoongArch in the future, feel free to Cc me.  I'll appreciate it. :)

Best Regards,
Enze

>
> Huacai
>
> On Tue, Aug 1, 2023 at 10:59=E2=80=AFAM Enze Li <lienze@kylinos.cn> wrote=
:
>>
>> Hi all,
>>
>> This patchset adds KFENCE support on LoongArch.
>>
>> To run the testcases, you will need to enable the following options,
>>
>> -> Kernel hacking
>>    [*] Tracers
>>        [*] Support for tracing block IO actions (NEW)
>>    -> Kernel Testing and Coverage
>>       <*> KUnit - Enable support for unit tests
>>
>> and then,
>>
>> -> Kernel hacking
>>    -> Memory Debugging
>>       [*] KFENCE: low-overhead sampling-based memory safety error detect=
or (NEW)
>>           <*> KFENCE integration test suite (NEW)
>>
>> With these options enabled, KFENCE will be tested during kernel startup.
>> And normally, you might get the following feedback,
>>
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>> [   35.326363 ] # kfence: pass:23 fail:0 skip:2 total:25
>> [   35.326486 ] # Totals: pass:23 fail:0 skip:2 total:25
>> [   35.326621 ] ok 1 kfence
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>>
>> you might notice that 2 testcases have been skipped.  If you tend to run
>> all testcases, please enable CONFIG_INIT_ON_FREE_DEFAULT_ON, you can
>> find it here,
>>
>> -> Security options
>>    -> Kernel hardening options
>>       -> Memory initialization
>>          [*] Enable heap memory zeroing on free by default
>>
>> and you might get all testcases passed.
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>> [   35.531860 ] # kfence: pass:25 fail:0 skip:0 total:25
>> [   35.531999 ] # Totals: pass:25 fail:0 skip:0 total:25
>> [   35.532135 ] ok 1 kfence
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
>>
>> v3:
>>    * Address Huacai's comments.
>>    * Fix a bug that Jackie Liu pointed out.
>>    * Rewrite arch_stack_walk() with the suggestion of Jinyang He.
>>
>> v2:
>>    * Address Huacai's comments.
>>    * Fix typos in commit message.
>>
>> Thanks,
>> Enze
>>
>> Enze Li (4):
>>   KFENCE: Defer the assignment of the local variable addr
>>   LoongArch: mm: Add page table mapped mode support
>>   LoongArch: Get stack without NMI when providing regs parameter
>>   LoongArch: Add KFENCE support
>>
>>  arch/loongarch/Kconfig               |  1 +
>>  arch/loongarch/include/asm/kfence.h  | 66 ++++++++++++++++++++++++++++
>>  arch/loongarch/include/asm/page.h    |  8 +++-
>>  arch/loongarch/include/asm/pgtable.h | 16 ++++++-
>>  arch/loongarch/kernel/stacktrace.c   | 18 ++++----
>>  arch/loongarch/mm/fault.c            | 22 ++++++----
>>  arch/loongarch/mm/pgtable.c          |  7 +++
>>  mm/kfence/core.c                     |  5 ++-
>>  8 files changed, 123 insertions(+), 20 deletions(-)
>>  create mode 100644 arch/loongarch/include/asm/kfence.h
>>
>> --
>> 2.34.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87a5v83606.fsf%40kylinos.cn.
