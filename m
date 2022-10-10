Return-Path: <kasan-dev+bncBDJOZX5EVMFRBZWPSCNAMGQEEPSMRXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 461395F9FEE
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 16:10:48 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id t15-20020a5d81cf000000b006bc1ca3ae00sf1757584iol.10
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Oct 2022 07:10:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665411047; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zk7o6NG//EOTybaVVvBFPBWJhgvNEOYJfLHyInEMvoODJpgE1OBDd5JSjhrTeaIbty
         T1zJ+ZFzy1Hk8RAXggrNqDhql8FvM3+E621Qtnt4oJTMtnHEHyzMlED6L9L/K7HLowYK
         0D3Swj0i1X0nhyZ7z4QbiP5yPjPKpsV2zm9+tZl2/xsd9NFJ97+learD8QSl2t7VM60c
         gyMPLFXdsSbGUQOgx2PSxO2bmMVA7VcWyUPAicyj8F7RoqXcX393VgitBW4iS8eLqXO4
         CGmqX0ZmhciEmJOHX9l1/9FOGSrQ4RyvYKUqoWD59GoBo10FVL89IrqHgoqqUTmMeKCY
         3u0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=XkZxqm9CxUtWQth2PMfn3dP4qtunHLdlcYR+YYKYK2w=;
        b=N+cChXWiDu7kE6uJRiKPbpmBWTjnHntvFkK8FELq/mm+yfi2pP8394fpY2beL1oC/w
         p1pw3NbENkfFx00+KUBwP7IGx4/Rh1QIz6qu9vyllhadu4hTWFoI/YxAznOr/Coavyi8
         jw+3RLSaFZgfK67gX586GDCbipQqmsOETUaeuOx+bDsFrTxJAoQ0GD1UvVhoHXdOQweb
         NPFNyC+LKLIE4uC00ufzH9Ri9rXPf2onTyGMOcAtkJ6odG52LjbWXKpKwEbG/ygNAxrk
         /K8pndyM5GeraCV5mBlGW5GZH0WWSG5UMPYUsXA6l0KddN+TgeIW0U92DrEv/CGWePv1
         Z+Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=c6TYWAx3;
       spf=pass (google.com: domain of nathanl@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nathanl@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XkZxqm9CxUtWQth2PMfn3dP4qtunHLdlcYR+YYKYK2w=;
        b=OqNQFnEa79sgM6CdV5TS096Kv0/RPA0Oaq1Own/mSgagzk6w3PKzTp+iXhHMmLKurn
         3N/rXhJ6jGNW2pk030BE9MR8Szpww9aWmQm/5KGE2oHHFQKmQ1zGR5np9w/NuLIZ6lOu
         27h1hp3F1OEVS0B+nawTA/8Ba0E0sRCHd0a2FqUt70+wl2sRECYaRRHs5i+CjeYdBd+o
         MNrpyWWzQbtrR0lWJLJc8H3rV+qZ9W4ZMNMeOEeXDB8KZPEaSHnHJkMpajd+dSVCCaJL
         w7s5jGa3O3QEWMYJGl5sB9hugjlxfrToSzvqchXcIL5LbSHKJz/vW/n5o1Xp7PvF3DZp
         UFMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XkZxqm9CxUtWQth2PMfn3dP4qtunHLdlcYR+YYKYK2w=;
        b=47XscG4NLk1SLnUDade3GSucot1uzjUYQ/KUFcvdzxeStxUmjeV1vZHQVbEiYds0S8
         SAOQc+7+4ZkB0Z0dmj/IxpNA8AMDCgJXNmJko/TzJdyPrkiZLt2Kh/Pr/8ErjZ0O6PCY
         obADzel1ESqoyNu9+PPCUPPAV/i7B+H2wttO0Da9hyxBIFY2P3w9gUK67LMdXMoPQQHV
         l7blnaaxj65Sik9BAktOflDFf/MatmEzr5w/lhai43WcxkNcRW6udCAC83R7bSChl8H0
         roJtfOtU/kdyLCDNm3zolcs4LXcmAL228Tf1b/v40nYAcNjP5PcxASWmBnfSTSr31jyH
         tKBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1HculUZ1iWrbjjAlE8tjuictyPQ1rS9pht/MrCmOvfHLWE8IL1
	HFQjvDSGAyR+zr+9cjys2hw=
X-Google-Smtp-Source: AMsMyM5xge5aS9HHo87JDgrZ7LB0xk6efshPWl4VXcQBzkDZwgQE/fEZNdv7OvSHFkS+a8vMKb/4XQ==
X-Received: by 2002:a02:94cf:0:b0:363:4a26:8cff with SMTP id x73-20020a0294cf000000b003634a268cffmr10215871jah.286.1665411046887;
        Mon, 10 Oct 2022 07:10:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1212:b0:2ea:c20b:a232 with SMTP id
 a18-20020a056e02121200b002eac20ba232ls2296378ilq.9.-pod-prod-gmail; Mon, 10
 Oct 2022 07:10:46 -0700 (PDT)
X-Received: by 2002:a05:6e02:e43:b0:2f5:739f:7d4d with SMTP id l3-20020a056e020e4300b002f5739f7d4dmr9330290ilk.100.1665411046470;
        Mon, 10 Oct 2022 07:10:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665411046; cv=none;
        d=google.com; s=arc-20160816;
        b=trp0dlajjfDgsCckrwF0P6BFbzBLpG8/KLT0cHBGJuqAJFo9YC1W3pBzjQhU2c2AsX
         3fqxt5gExr7hFOQwHK3PD6JAnfH7sMrF2niRL9l9AELWkVhNARt6jAwRuixqhfCOhDtx
         cZog1p1xZtS2Yii3W0RH6teSYQWZyuAOkjSdYuhRld2qHQQVZeN+bIWVx/EFckkTm5Yu
         I/DP7ye1iBr8lxBMb5D1atKksNQNK1utUH2LXVCy+CDhff+AoIL5+kLZh+YdOAa6EYEL
         tv27WE1hW742JqQpJjI3oyoVCGNrFN0TVTQNyecrRRkwIytmLAFdFVJ37FsRtkQFSUwE
         xOiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=kVVtL9sg5geUzXWpD0lphCXAA2C4tqRVjLqbQUC6IoA=;
        b=Gn68Gt3WZckJI8ix1KxvTZEAavbQo2JpOxl/KfGXyTRiC1/PCIlzioDH2luVzA9JSk
         ekrkUaMB+0hnyuMrMmZWrqsvxyHKwURySdMn3LpPhqFcEb2ycX7VoGbStoa2zv/pQdQl
         ZAScF+EcIa0huZZH+wXtuOBUfn8oR8blkyD0auvSx85vuK8zFhQai1bpgRoVjW/+UIuI
         ajRrOFwciwlGN8ZNJL8yGqMeS/4doQeD6nxnse3bPWPn8gFyjUHELMA1SZJ0qtdo+3lm
         gsjTnrC2/50Jtf4Sws+OG2XAWMLHZLByyQ2g5zpo6y3bTuTR7WFyO1RuHFSsXWInQdO2
         bCNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=c6TYWAx3;
       spf=pass (google.com: domain of nathanl@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nathanl@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id r19-20020a02c853000000b00363c6583241si44484jao.4.2022.10.10.07.10.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Oct 2022 07:10:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathanl@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098419.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 29ADYTDN024581;
	Mon, 10 Oct 2022 14:10:40 GMT
Received: from ppma02dal.us.ibm.com (a.bd.3ea9.ip4.static.sl-reverse.com [169.62.189.10])
	by mx0b-001b2d01.pphosted.com (PPS) with ESMTPS id 3k3ju7743r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 10 Oct 2022 14:10:39 +0000
Received: from pps.filterd (ppma02dal.us.ibm.com [127.0.0.1])
	by ppma02dal.us.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 29AE5rH0017672;
	Mon, 10 Oct 2022 14:10:39 GMT
Received: from b03cxnp08026.gho.boulder.ibm.com (b03cxnp08026.gho.boulder.ibm.com [9.17.130.18])
	by ppma02dal.us.ibm.com with ESMTP id 3k30u9r1q8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 10 Oct 2022 14:10:39 +0000
Received: from smtpav03.dal12v.mail.ibm.com ([9.208.128.129])
	by b03cxnp08026.gho.boulder.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 29AEAew166191700
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 10 Oct 2022 14:10:40 GMT
Received: from smtpav03.dal12v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A4C0158056;
	Mon, 10 Oct 2022 14:10:37 +0000 (GMT)
Received: from smtpav03.dal12v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8C63E5803F;
	Mon, 10 Oct 2022 14:10:37 +0000 (GMT)
Received: from localhost (unknown [9.163.68.247])
	by smtpav03.dal12v.mail.ibm.com (Postfix) with ESMTP;
	Mon, 10 Oct 2022 14:10:37 +0000 (GMT)
From: Nathan Lynch <nathanl@linux.ibm.com>
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
        "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
        kasan-dev
 <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
In-Reply-To: <87h70for01.fsf@mpe.ellerman.id.au>
References: <20221004223724.38707-1-nathanl@linux.ibm.com>
 <874jwhpp6g.fsf@mpe.ellerman.id.au>
 <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
 <87h70for01.fsf@mpe.ellerman.id.au>
Date: Mon, 10 Oct 2022 09:10:37 -0500
Message-ID: <8735bvbwgy.fsf@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: X2AAXZAOir1-kLJTxJrXSE4ZcIOLtkkR
X-Proofpoint-ORIG-GUID: X2AAXZAOir1-kLJTxJrXSE4ZcIOLtkkR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.895,Hydra:6.0.528,FMLib:17.11.122.1
 definitions=2022-10-10_08,2022-10-10_02,2022-06-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 adultscore=0
 lowpriorityscore=0 spamscore=0 bulkscore=0 priorityscore=1501
 clxscore=1011 mlxscore=0 suspectscore=0 malwarescore=0 impostorscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2209130000 definitions=main-2210100084
X-Original-Sender: nathanl@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=c6TYWAx3;       spf=pass (google.com:
 domain of nathanl@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=nathanl@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=ibm.com
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

Michael Ellerman <mpe@ellerman.id.au> writes:
> Christophe Leroy <christophe.leroy@csgroup.eu> writes:
>> + KASAN list
>>
>> Le 06/10/2022 =C3=A0 06:10, Michael Ellerman a =C3=A9crit=C2=A0:
>>> Nathan Lynch <nathanl@linux.ibm.com> writes:
>>>> kasan is known to crash at boot on book3s_64 with non-radix MMU. As
>>>> noted in commit 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only
>>>> KASAN support"):
>>>>
>>>>    A kernel with CONFIG_KASAN=3Dy will crash during boot on a machine
>>>>    using HPT translation because not all the entry points to the
>>>>    generic KASAN code are protected with a call to kasan_arch_is_ready=
().
>>>=20
>>> I guess I thought there was some plan to fix that.
>>
>> I was thinking the same.
>>
>> Do we have a list of the said entry points to the generic code that are=
=20
>> lacking a call to kasan_arch_is_ready() ?
>>
>> Typically, the BUG dump below shows that kasan_byte_accessible() is=20
>> lacking the check. It should be straight forward to add=20
>> kasan_arch_is_ready() check to kasan_byte_accessible(), shouldn't it ?
>
> Yes :)
>
> And one other spot, but the patch below boots OK for me. I'll leave it
> running for a while just in case there's a path I've missed.

It works for me too, thanks (p8 pseries qemu).

This avoids the boot-time oops, but kasan remains unimplemented for hash
mmu. Raising the question: with the trivial crashes addressed, is the
current message ('KASAN not enabled as it requires radix!') sufficient
to notify developers (such as me, a week ago) who mean to use kasan on a
book3s platform, unaware that it's radix-only? Would a WARN or something
more prominent still be justified?

I guess people will figure it out as soon as they think to search the
kernel log for 'KASAN'...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8735bvbwgy.fsf%40linux.ibm.com.
