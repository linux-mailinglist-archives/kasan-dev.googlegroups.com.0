Return-Path: <kasan-dev+bncBDE5LFWXQAIRBZ7YZ6AQMGQEGM5Z6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id EBE03321F5D
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 19:48:08 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id e10sf6577611oie.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 10:48:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614019687; cv=pass;
        d=google.com; s=arc-20160816;
        b=T6wWhot7H3XoKEhE0OOirh3RIJhUUA6oSv/XYmfYQvgreZuMFLGEMdn87ZRRMZqkkd
         WoY/4MHlJVAvvrqN8twVs24KWgzu5RUIL0ipbfrVMzssEDBKZcirAU3GB8JugPInkJs+
         w+KhFrXcPmptOgWtItXRgdT6uO0SxM+ewK/5uOoIbJkYt9NP/xxRFGH+ZWgY1cVtS+tP
         zDkFJDH5CDBIp0Mr6H3v5WUiRmtQHWx1QnVttxzQsjkAvs4XcoccpdTfVkJxp6dljQcL
         89gl8EqM3exPPq7+Z1ttVTa8drKf/IJhIzDt/VipJIbZtweqNZDhZN0NJk/VNJWBGjhP
         3+8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=GqCFKlRKpd2objk0DkyCVS0LfzyQLX7Qv/lJbcn30zg=;
        b=MJW/H/6vpFhROVMyInNLtQuZOnPTwhvehQRUwI8/eS29MEqhwEPK/vBcNQgshxFXXR
         i5I/g9veXU2OtLO9Q+cVaY/20vPDRCZ1/tlOZosj1ahDuLLtLf0CSCx5KVfII88C9TzU
         T4otOVgoMrJkuY6OZY2CK7N/pIfGBp0Grl5kMSEotmpp4G6FHOVMWmgQsKCQf3QysGzi
         WftfsxdCYlsUspcCE+1RFa9xL/vDvG2h83miZEte6snVqCV3xkAQlD6d8v/EHhYmxxlS
         7THTZOVSf54bj976JdzDfc70Xt7ggsbjMwUF+C5cxyqQ111fSgA0/tmG1Ci19b0Pc9fX
         yl+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IFr69xQA;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GqCFKlRKpd2objk0DkyCVS0LfzyQLX7Qv/lJbcn30zg=;
        b=CRYrCmukoi+r6/xPyZqxaYj528k7hC8Qoo47f+Z34U2mB1tFdCWXOwc4sgaCaO6fIR
         XvyhnxJBqU+++Vjc1PZ3LrXbG3Dyh7LMX2asOun+0PO3GlCsolyRMU89grqLP/Io1jqd
         rr0+XDgdrs0GPpDIv6DsQNF69oXfSGKGndvohYf7rm2mksxA4tGBidJsZe9vz1iVLuA9
         /rTamuSA/3HwDWQQHhuv6TISKqD5j0r100DupWG7hRfsLkijkoZa8fTXHw3TIMDz5/rn
         ZA5fF0xP55YxgIU2+6dgCTvWmMQmV8sxegf640DC4ZN2guARe2GT6Yxia3GKW/OHDtXf
         gUEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GqCFKlRKpd2objk0DkyCVS0LfzyQLX7Qv/lJbcn30zg=;
        b=dASjrsJEsqx5cSYUi3MdX7G60WYt4Geaq8SyWiAmhMONqlUcWvlj1WQBgxl+WAcFaJ
         mu5rksfZ/epgnmSvnaXqwIYpTNBdL1klFX086MQ5k9H/AWN/LthTvpv55Kfmm3kCQN/E
         k015xn/l0MKOm0JHo0jAf//HWfPbwxl6x+6kORerwUk/ZL21kl8/jv2F1NPLZ0dsupSP
         E22RAIX8Kc/GBmVwkCZ+3IVeTAPOC7hFqzukWNDouSiddaxR/hOqJrT01Ad+zpXtQ3AU
         iwhYIqxe8TlOkdqmMrjzeiPGfJ4vFZGYJi3fHuq/77CARAo/ztayiZ/H5hNRDklD3V4E
         yEmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533A68xI/KavlEKM4yDvqpqSIyapz5bOY8yTwyypvaLQJgWt7AVm
	JZERkGlfSWvrbJ7D+cs4qCs=
X-Google-Smtp-Source: ABdhPJwwfbGkYtuL4wmOu9pIfWadRaI0NuhkKTEzSg+1pTxeAq/yLWTyGVh6YU4ZsGyYyqWDkdxjBw==
X-Received: by 2002:a9d:7e8f:: with SMTP id m15mr10110040otp.165.1614019687580;
        Mon, 22 Feb 2021 10:48:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7d86:: with SMTP id j6ls1733561otn.11.gmail; Mon, 22 Feb
 2021 10:48:07 -0800 (PST)
X-Received: by 2002:a05:6830:16d6:: with SMTP id l22mr2049015otr.121.1614019686931;
        Mon, 22 Feb 2021 10:48:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614019686; cv=none;
        d=google.com; s=arc-20160816;
        b=vBlDRM1cuowOAClsUbkdQ1hsGlELuRSeo1TbsnQBYGTkMolGT8s2iQoe4T2nC+53zu
         EBERXRO+4pxs/ZFksjySxwIs0fGeQ/gY/UU7Z+zdwRG5dNahfW3hXYt9CbMbVTp2SmVf
         jxJ0jucLHJIvpdfIM/g79HGXJDNinDgQ2uhRS8DkdsYR28D9x/FSLxwgPpRSdMQvNIOx
         sOQYWOZ262ucva8AtovEJ776oy7hDOgBAoY4TblyERXP99d9fILes3sdc0RrgrJSFaGQ
         sHjwoa08OzPV1CR8a/cLnna8R9kkR/zM6VFFR+UlhSXvEnElYrtT9NUAiAO0SRsDR10T
         b0JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=7g8nMPK0BWDP02m4h8rVpPLI++nL8C+0dAkk5BW4xow=;
        b=t3NCm4JGdR4WN7XAmC6e3Z3r/V0Rg1KghriO+y27FseGAic8NrwzN2STe1pDlpmjPj
         6L04WJR1mo2zck2A39l+CwPeTa026UvygLaYzQD5ageZAIkEq0R26LRPGkb33+CImjlR
         oGM6OY0BjS4Qs62SZRB3eNqX7fQPIavD1AP1Myapo7dPLRDJo8OpeEhnWsyCjV00RISh
         D0MrjwCJS7zlw5pO6O4UTCHwAmG0nIKCrURUnunTYZL//buPp+LNSO3Ej0Sajg0r1Jai
         +RncOP5NlGtxqBKjS24wVb9J5M/FyIIOStDYjP9RnrGCKIYwJzakSyNk7zJU+vSU/nE3
         CxXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IFr69xQA;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id n12si1019467oie.2.2021.02.22.10.48.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Feb 2021 10:48:06 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098396.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 11MIgiTv158848;
	Mon, 22 Feb 2021 13:47:48 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vhy78k8s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 22 Feb 2021 13:47:47 -0500
Received: from m0098396.ppops.net (m0098396.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 11MIgvj2159799;
	Mon, 22 Feb 2021 13:47:33 -0500
Received: from ppma04ams.nl.ibm.com (63.31.33a9.ip4.static.sl-reverse.com [169.51.49.99])
	by mx0a-001b2d01.pphosted.com with ESMTP id 36vhy78j7x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 22 Feb 2021 13:47:32 -0500
Received: from pps.filterd (ppma04ams.nl.ibm.com [127.0.0.1])
	by ppma04ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 11MIgCZM014626;
	Mon, 22 Feb 2021 18:45:52 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma04ams.nl.ibm.com with ESMTP id 36tt289wmu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 22 Feb 2021 18:45:51 +0000
Received: from d06av25.portsmouth.uk.ibm.com (d06av25.portsmouth.uk.ibm.com [9.149.105.61])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 11MIjnkg43712902
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 22 Feb 2021 18:45:49 GMT
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AFA0911C05B;
	Mon, 22 Feb 2021 18:45:49 +0000 (GMT)
Received: from d06av25.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BCDF211C04A;
	Mon, 22 Feb 2021 18:45:45 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.145.51.238])
	by d06av25.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Mon, 22 Feb 2021 18:45:45 +0000 (GMT)
Date: Mon, 22 Feb 2021 20:45:43 +0200
From: Mike Rapoport <rppt@linux.ibm.com>
To: Konrad Rzeszutek Wilk <konrad@darnok.org>
Cc: David Hildenbrand <david@redhat.com>,
        George Kennedy <george.kennedy@oracle.com>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will.deacon@arm.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>,
        Evgenii Stepanov <eugenis@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Christoph Hellwig <hch@infradead.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        LKML <linux-kernel@vger.kernel.org>,
        Dhaval Giani <dhaval.giani@oracle.com>
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <20210222184543.GA1741768@linux.ibm.com>
References: <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <4c7351e2-e97c-e740-5800-ada5504588aa@redhat.com>
 <20210222174036.GA399355@fedora>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20210222174036.GA399355@fedora>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.369,18.0.761
 definitions=2021-02-22_06:2021-02-22,2021-02-22 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 phishscore=0 mlxlogscore=999 spamscore=0 suspectscore=0 adultscore=0
 clxscore=1011 priorityscore=1501 lowpriorityscore=0 malwarescore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102220163
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IFr69xQA;       spf=pass (google.com:
 domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Feb 22, 2021 at 12:40:36PM -0500, Konrad Rzeszutek Wilk wrote:
> On Mon, Feb 22, 2021 at 05:39:29PM +0100, David Hildenbrand wrote:
> > On 22.02.21 17:13, David Hildenbrand wrote:
> > > On 22.02.21 16:13, George Kennedy wrote:
> > > >=20
> > > >=20
> > > > On 2/22/2021 4:52 AM, David Hildenbrand wrote:
> > > > > On 20.02.21 00:04, George Kennedy wrote:
> > > > > >=20
> > > > > >=20
> > > > > > On 2/19/2021 11:45 AM, George Kennedy wrote:
> > > > > > >=20
> > > > > > >=20
> > > > > > > On 2/18/2021 7:09 PM, Andrey Konovalov wrote:
> > > > > > > > On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
> > > > > > > > <george.kennedy@oracle.com> wrote:
> > > > > > > > >=20
> > > > > > > > >=20
> > > > > > > > > On 2/18/2021 3:55 AM, David Hildenbrand wrote:
> > > > > > > > > > On 17.02.21 21:56, Andrey Konovalov wrote:
> > > > > > > > > > > During boot, all non-reserved memblock memory is expo=
sed to the
> > > > > > > > > > > buddy
> > > > > > > > > > > allocator. Poisoning all that memory with KASAN lengt=
hens boot
> > > > > > > > > > > time,
> > > > > > > > > > > especially on systems with large amount of RAM. This =
patch makes
> > > > > > > > > > > page_alloc to not call kasan_free_pages() on all new =
memory.
> > > > > > > > > > >=20
> > > > > > > > > > > __free_pages_core() is used when exposing fresh memor=
y during
> > > > > > > > > > > system
> > > > > > > > > > > boot and when onlining memory during hotplug. This pa=
tch adds a new
> > > > > > > > > > > FPI_SKIP_KASAN_POISON flag and passes it to __free_pa=
ges_ok()
> > > > > > > > > > > through
> > > > > > > > > > > free_pages_prepare() from __free_pages_core().
> > > > > > > > > > >=20
> > > > > > > > > > > This has little impact on KASAN memory tracking.
> > > > > > > > > > >=20
> > > > > > > > > > > Assuming that there are no references to newly expose=
d pages
> > > > > > > > > > > before they
> > > > > > > > > > > are ever allocated, there won't be any intended (but =
buggy)
> > > > > > > > > > > accesses to
> > > > > > > > > > > that memory that KASAN would normally detect.
> > > > > > > > > > >=20
> > > > > > > > > > > However, with this patch, KASAN stops detecting wild =
and large
> > > > > > > > > > > out-of-bounds accesses that happen to land on a fresh=
 memory page
> > > > > > > > > > > that
> > > > > > > > > > > was never allocated. This is taken as an acceptable t=
rade-off.
> > > > > > > > > > >=20
> > > > > > > > > > > All memory allocated normally when the boot is over k=
eeps getting
> > > > > > > > > > > poisoned as usual.
> > > > > > > > > > >=20
> > > > > > > > > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.co=
m>
> > > > > > > > > > > Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
> > > > > > > > > > Not sure this is the right thing to do, see
> > > > > > > > > >=20
> > > > > > > > > > https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536=
c529860@oracle.com
> > > > > > > > > >=20
> > > > > > > > > >=20
> > > > > > > > > >=20
> > > > > > > > > > Reversing the order in which memory gets allocated + us=
ed during
> > > > > > > > > > boot
> > > > > > > > > > (in a patch by me) might have revealed an invalid memor=
y access
> > > > > > > > > > during
> > > > > > > > > > boot.
> > > > > > > > > >=20
> > > > > > > > > > I suspect that that issue would no longer get detected =
with your
> > > > > > > > > > patch, as the invalid memory access would simply not ge=
t detected.
> > > > > > > > > > Now, I cannot prove that :)
> > > > > > > > > Since David's patch we're having trouble with the iBFT AC=
PI table,
> > > > > > > > > which
> > > > > > > > > is mapped in via kmap() - see acpi_map() in "drivers/acpi=
/osl.c".
> > > > > > > > > KASAN
> > > > > > > > > detects that it is being used after free when ibft_init()=
 accesses
> > > > > > > > > the
> > > > > > > > > iBFT table, but as of yet we can't find where it get's fr=
eed (we've
> > > > > > > > > instrumented calls to kunmap()).
> > > > > > > > Maybe it doesn't get freed, but what you see is a wild or a=
 large
> > > > > > > > out-of-bounds access. Since KASAN marks all memory as freed=
 during the
> > > > > > > > memblock->page_alloc transition, such bugs can manifest as
> > > > > > > > use-after-frees.
> > > > > > >=20
> > > > > > > It gets freed and re-used. By the time the iBFT table is acce=
ssed by
> > > > > > > ibft_init() the page has been over-written.
> > > > > > >=20
> > > > > > > Setting page flags like the following before the call to kmap=
()
> > > > > > > prevents the iBFT table page from being freed:
> > > > > >=20
> > > > > > Cleaned up version:
> > > > > >=20
> > > > > > diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
> > > > > > index 0418feb..8f0a8e7 100644
> > > > > > --- a/drivers/acpi/osl.c
> > > > > > +++ b/drivers/acpi/osl.c
> > > > > > @@ -287,9 +287,12 @@ static void __iomem *acpi_map(acpi_physica=
l_address
> > > > > > pg_off, unsigned long pg_sz)
> > > > > >=20
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
> > > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pf=
n_to_page(pfn);
> > > > > > +
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (pg_sz =
> PAGE_SIZE)
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 return NULL;
> > > > > > -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __f=
orce *)kmap(pfn_to_page(pfn));
> > > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 SetPageReserved(page);
> > > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __f=
orce *)kmap(page);
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 } else
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acp=
i_os_ioremap(pg_off, pg_sz);
> > > > > >   =C2=A0 =C2=A0}
> > > > > > @@ -299,9 +302,12 @@ static void acpi_unmap(acpi_physical_addre=
ss
> > > > > > pg_off, void __iomem *vaddr)
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn;
> > > > > >=20
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
> > > > > > -=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn))
> > > > > > -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(pfn_to_page(pfn))=
;
> > > > > > -=C2=A0=C2=A0=C2=A0 else
> > > > > > +=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
> > > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pf=
n_to_page(pfn);
> > > > > > +
> > > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ClearPageReserved(page);
> > > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(page);
> > > > > > +=C2=A0=C2=A0=C2=A0 } else
> > > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 iounmap(va=
ddr);
> > > > > >   =C2=A0 =C2=A0}
> > > > > >=20
> > > > > > David, the above works, but wondering why it is now necessary. =
kunmap()
> > > > > > is not hit. What other ways could a page mapped via kmap() be u=
nmapped?
> > > > > >=20
> > > > >=20
> > > > > Let me look into the code ... I have little experience with ACPI
> > > > > details, so bear with me.
> > > > >=20
> > > > > I assume that acpi_map()/acpi_unmap() map some firmware blob that=
 is
> > > > > provided via firmware/bios/... to us.
> > > > >=20
> > > > > should_use_kmap() tells us whether
> > > > > a) we have a "struct page" and should kmap() that one
> > > > > b) we don't have a "struct page" and should ioremap.
> > > > >=20
> > > > > As it is a blob, the firmware should always reserve that memory r=
egion
> > > > > via memblock (e.g., memblock_reserve()), such that we either
> > > > > 1) don't create a memmap ("struct page") at all (-> case b) )
> > > > > 2) if we have to create e memmap, we mark the page PG_reserved an=
d
> > > > >   =C2=A0=C2=A0 *never* expose it to the buddy (-> case a) )
> > > > >=20
> > > > >=20
> > > > > Are you telling me that in this case we might have a memmap for t=
he HW
> > > > > blob that is *not* PG_reserved? In that case it most probably got
> > > > > exposed to the buddy where it can happily get allocated/freed.
> > > > >=20
> > > > > The latent BUG would be that that blob gets exposed to the system=
 like
> > > > > ordinary RAM, and not reserved via memblock early during boot.
> > > > > Assuming that blob has a low physical address, with my patch it w=
ill
> > > > > get allocated/used a lot earlier - which would mean we trigger th=
is
> > > > > latent BUG now more easily.
> > > > >=20
> > > > > There have been similar latent BUGs on ARM boards that my patch
> > > > > discovered where special RAM regions did not get marked as reserv=
ed
> > > > > via the device tree properly.
> > > > >=20
> > > > > Now, this is just a wild guess :) Can you dump the page when mapp=
ing
> > > > > (before PageReserved()) and when unmapping, to see what the state=
 of
> > > > > that memmap is?
> > > >=20
> > > > Thank you David for the explanation and your help on this,
> > > >=20
> > > > dump_page() before PageReserved and before kmap() in the above patc=
h:
> > > >=20
> > > > [=C2=A0=C2=A0=C2=A0 1.116480] ACPI: Core revision 20201113
> > > > [=C2=A0=C2=A0=C2=A0 1.117628] XXX acpi_map: about to call kmap()...
> > > > [=C2=A0=C2=A0=C2=A0 1.118561] page:ffffea0002f914c0 refcount:0 mapc=
ount:0
> > > > mapping:0000000000000000 index:0x0 pfn:0xbe453
> > > > [=C2=A0=C2=A0=C2=A0 1.120381] flags: 0xfffffc0000000()
> > > > [=C2=A0=C2=A0=C2=A0 1.121116] raw: 000fffffc0000000 ffffea0002f914c=
8 ffffea0002f914c8
> > > > 0000000000000000
> > > > [=C2=A0=C2=A0=C2=A0 1.122638] raw: 0000000000000000 000000000000000=
0 00000000ffffffff
> > > > 0000000000000000
> > > > [=C2=A0=C2=A0=C2=A0 1.124146] page dumped because: acpi_map pre Set=
PageReserved
> > > >=20
> > > > I also added dump_page() before unmapping, but it is not hit. The
> > > > following for the same pfn now shows up I believe as a result of se=
tting
> > > > PageReserved:
> > > >=20
> > > > [=C2=A0=C2=A0 28.098208] BUG:Bad page state in process mo dprobe=C2=
=A0 pfn:be453
> > > > [=C2=A0=C2=A0 28.098394] page:ffffea0002f914c0 refcount:0 mapcount:=
0
> > > > mapping:0000000000000000 index:0x1 pfn:0xbe453
> > > > [=C2=A0=C2=A0 28.098394] flags: 0xfffffc0001000(reserved)
> > > > [=C2=A0=C2=A0 28.098394] raw: 000fffffc0001000 dead000000000100 dea=
d000000000122
> > > > 0000000000000000
> > > > [=C2=A0=C2=A0 28.098394] raw: 0000000000000001 0000000000000000 000=
00000ffffffff
> > > > 0000000000000000
> > > > [=C2=A0=C2=A0 28.098394] page dumped because: PAGE_FLAGS_CHECK_AT_P=
REP flag(s) set
> > > > [=C2=A0=C2=A0 28.098394] page_owner info is not present (never set?=
)
> > > > [=C2=A0=C2=A0 28.098394] Modules linked in:
> > > > [=C2=A0=C2=A0 28.098394] CPU: 2 PID: 204 Comm: modprobe Not tainted=
 5.11.0-3dbd5e3 #66
> > > > [=C2=A0=C2=A0 28.098394] Hardware name: QEMU Standard PC (i440FX + =
PIIX, 1996),
> > > > BIOS 0.0.0 02/06/2015
> > > > [=C2=A0=C2=A0 28.098394] Call Trace:
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 dump_stack+0xdb/0x120
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 bad_page.cold.108+0xc6/0xcb
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 check_new_page_bad+0x47/0xa0
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 get_page_from_freelist+0x30cd/0x5730
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __isolate_free_page+0x4f0/0x4f0
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? init_object+0x7e/0x90
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __alloc_pages_slowpath.constprop.1=
03+0x2110/0x2110
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 alloc_pages_vma+0xe2/0x560
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 do_fault+0x194/0x12c0
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 __handle_mm_fault+0x1650/0x26c0
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? copy_page_range+0x1350/0x1350
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 handle_mm_fault+0x1f9/0x810
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 do_user_addr_fault+0x6f7/0xca0
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 exc_page_fault+0xaf/0x1a0
> > > > [=C2=A0=C2=A0 28.098394]=C2=A0 asm_exc_page_fault+0x1e/0x30
> > > > [=C2=A0=C2=A0 28.098394] RIP: 0010:__clear_user+0x30/0x60
> > >=20
> > > I think the PAGE_FLAGS_CHECK_AT_PREP check in this instance means tha=
t
> > > someone is trying to allocate that page with the PG_reserved bit set.
> > > This means that the page actually was exposed to the buddy.
> > >=20
> > > However, when you SetPageReserved(), I don't think that PG_buddy is s=
et
> > > and the refcount is 0. That could indicate that the page is on the bu=
ddy
> > > PCP list. Could be that it is getting reused a couple of times.
> > >=20
> > > The PFN 0xbe453 looks a little strange, though. Do we expect ACPI tab=
les
> > > close to 3 GiB ? No idea. Could it be that you are trying to map a wr=
ong
> > > table? Just a guess.
>=20
> Nah, ACPI MADT enumerates the table and that is the proper location of it=
.
> >=20
> > ... but I assume ibft_check_device() would bail out on an invalid check=
sum.
> > So the question is, why is this page not properly marked as reserved
> > already.
>=20
> The ibft_check_device ends up being called as module way way after the
> kernel has cleaned the memory.
>=20
> The funny thing about iBFT is that (it is also mentioned in the spec)
> that the table can resize in memory .. or in the ACPI regions (which

                   ^ reside I presume?

> have no E820_RAM and are considered "MMIO" regions).
>=20
> Either place is fine, so it can be in either RAM or MMIO :-(

I'd say that the tables in this case are in E820_RAM, because with MMIO we
wouldn't get to kmap() at the first place.
It can be easily confirmed by comparing the problematic address with
/proc/iomem.

Can't say I have a clue about what's going on there, but the theory that
somehow iBFT table does not get PG_Reserved during boot makes sense.

Do you see "iBFT found at 0x<addr>" early in the kernel log?

I don't know if ACPI relocates the tables, but I could not find anywhere
that it reserves the original ones. The memblock_reserve() in
acpi_table_upgrade() is merely a part of open coded memblock allocation.

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210222184543.GA1741768%40linux.ibm.com.
