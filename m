Return-Path: <kasan-dev+bncBCO25SXBYEMBB2XO5W7AMGQERDY3MSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A467A69E06
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 03:03:32 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5fe86d21b5csf150345eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 19:03:32 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742436203; x=1743041003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N+Es02CDbyhisZjSVW8wcf0t4QrJFsXcXw4HRQ4jZgc=;
        b=Y7iRff8WyRv98LdgC6+rMCNvSlEopJ9eB1w0X9sIPHiynnRYNUVnlzk6wFFo3kGci4
         CKXOC54+2XAWyTjaFEHYNbXtKa3vrDxjPTJCrOZcsuQAnUtzARf6y+afZU/X4VmM/BgY
         wUkJUIexvEhLoOtoTA2dF12CmQ5XJ0dTVy1524XBhaTl2exN1Tsb55SUrnzcUxvDUVRF
         gCIF/JU70vRDMK7snX6KPwu5lwgz2hNmYSjlp6s2uNPGsWnkjMp3+nLDf3Sztbvt2Ezh
         Y7DzbFC0h+ZmlkOrdfrHPzctxLwRk662NfJ+T/GqBi/kPsQOywPFvZTGEF7xlFIY6Xtk
         4p/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742436203; x=1743041003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N+Es02CDbyhisZjSVW8wcf0t4QrJFsXcXw4HRQ4jZgc=;
        b=e/QmXjd+X6rjlIsK1f20e7HYel7H7jZ08yXI8iURd1QXgKKsEHkJkyxOWEVJHXnoXe
         1iIoFyJ0tB7CIqcDkutWWchEnA3V+OxivtQyXDfKtn6h9K42vtbyFqSnqht8zgh1QKOg
         Sg5TykX+qZLiXh2sQ6d4B/R6VQ3q4WLMgDbOxsiIVn8sC8cspzcphYAAurMZNd4ZemTE
         ZaT1JL3tCFtuoEakdr4hTKHTB6fOzloDHT+mzvbcf5tAi/DMfE6mCS2y8rJPggvLPC71
         4gkPL2/Rb20kVVqoCIUelkXtoA9b1Zzu9Ad1uea8DqvnqDyNy30B2PU6oLPzZCV3tHgo
         b2/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742436203; x=1743041003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N+Es02CDbyhisZjSVW8wcf0t4QrJFsXcXw4HRQ4jZgc=;
        b=PH2ZqvsuxIuBSOeDP43p88oT0UaXTWq56dmb5NUbxfJlVnqbObcM+2FKTORlufpIP6
         5+GVDJvm2ceDtFwy4w4JjxYCu1hFSHyrnM3CjqOXEtdSCYBhyWu+ITR7YSuzRNRkirxm
         bSO2U5weT7pHhudosGd9DDS3y7iNjaGITzlwK0WU5/N2v0a2uLTAOB2YrGPjV+7MZZVF
         vHVCHLsQ8Slp/22bK1qynRCP8DkqfCZTNL76wbrU3ZNz0xy1d05RL4QyovWd9jkcx4Ah
         ahvetjce7LFEsr4cs5z9sXy1yIzjEK1Jr+pR5eXv6U40dJ5uc/7Mi5omEN+G2Vq74GCb
         Q++g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCWK6eZpq+9fLqc9Jy3M5muF8k/NvpcVQpBtd8+53henOyOrJRz/xKSpJco8Vu+uHWLcV6Ywdw==@lfdr.de
X-Gm-Message-State: AOJu0Yyh3W/f/NYteZjuHYNudc2AHqNSzpVSvyNOtqppivG9DIC4ZfSV
	T4DUWfSQI1iYHD9nYKKLzKlzLiz5AafXusF/m0tAagqL/LyENxXe
X-Google-Smtp-Source: AGHT+IHsau0O2Epq91lnu6D8755/LMHbWK2fqNO5T+Mvqqm0wjDz1Ai8Iinwy/dlNnZxACzWNAqU0w==
X-Received: by 2002:a05:6820:4a81:b0:601:b8df:a56f with SMTP id 006d021491bc7-6021e42b65cmr2763948eaf.3.1742436202882;
        Wed, 19 Mar 2025 19:03:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKwQrv0Vj8x6q+tmfu0Kpo+QA3d4s73WkKUgIhNLntSqg==
Received: by 2002:a4a:e605:0:b0:600:3d56:c122 with SMTP id 006d021491bc7-6022945aea5ls100281eaf.0.-pod-prod-04-us;
 Wed, 19 Mar 2025 19:03:22 -0700 (PDT)
X-Received: by 2002:a05:6808:1455:b0:3f8:effc:938 with SMTP id 5614622812f47-3fead5e9a87mr4811775b6e.34.1742436201894;
        Wed, 19 Mar 2025 19:03:21 -0700 (PDT)
Date: Wed, 19 Mar 2025 19:03:21 -0700 (PDT)
From: ye zhenyu <zhenyuy505@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <3f88fc09-ae66-4a1c-9b87-46928b67be20n@googlegroups.com>
Subject: Enable memory tagging in pixel 8a kernel
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_170874_696940131.1742436201253"
X-Original-Sender: zhenyuy505@gmail.com
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

------=_Part_170874_696940131.1742436201253
Content-Type: multipart/alternative; 
	boundary="----=_Part_170875_462490627.1742436201253"

------=_Part_170875_462490627.1742436201253
Content-Type: text/plain; charset="UTF-8"

Hello everyone, I have a Pixel 8a and would like to enable MTE in the 
kernel. However, whenever I try to set or get tags using stg/ldg, it always 
returns 0. Does anyone know why and could you please help me? Thank you 
very much.
some registers set :
 TCR_EL1 : 0x051001f2b5593519 : SCTLR_EL1 : 0x02000d38fc74f99d : MAIR_EL1 : 
0x0000f4040044f0ff : GCR_EL1 : 0x0000000000010000 : hcr_el2 : 
0x0100030080080001
(I can not get the scr_el3)
the page table entry of associate address : 0x6800008a2b9707

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3f88fc09-ae66-4a1c-9b87-46928b67be20n%40googlegroups.com.

------=_Part_170875_462490627.1742436201253
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hello everyone, I have a Pixel 8a and would like to enable MTE in the kerne=
l. However, whenever I try to set or get tags using stg/ldg, it always retu=
rns 0. Does anyone know why and could you please help me? Thank you very mu=
ch.<br />some registers set :<br />=C2=A0TCR_EL1 : 0x051001f2b5593519 : SCT=
LR_EL1 : 0x02000d38fc74f99d : MAIR_EL1 : 0x0000f4040044f0ff : GCR_EL1 : 0x0=
000000000010000 : hcr_el2 : 0x0100030080080001<br />(I can not get the scr_=
el3)<br />the page table entry of associate address : 0x6800008a2b9707<br /=
>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/3f88fc09-ae66-4a1c-9b87-46928b67be20n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/3f88fc09-ae66-4a1c-9b87-46928b67be20n%40googlegroups.com</a>.<br />

------=_Part_170875_462490627.1742436201253--

------=_Part_170874_696940131.1742436201253--
