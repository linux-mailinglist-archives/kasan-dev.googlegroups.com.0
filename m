Return-Path: <kasan-dev+bncBAABBZEZXTWAKGQEYAFQELA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 246C0C1011
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Sep 2019 09:33:58 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id r21sf989459uao.16
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Sep 2019 00:33:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569656037; cv=pass;
        d=google.com; s=arc-20160816;
        b=QailgFSysdJ/eTp5xG9xhyHxG+8FVzqpbmLk57mFUZFSsixi9wSl1RKsfNvl36R6Y2
         NXc+Ee9tX3ReZ3NZP0/8h1bzWxGiHI6/PUhKOwABonSOYvB/oiJirMP2NItz/zQQRSIm
         FuPStPBezjSMOH++d/fdxKwavuwWCOrat2TBN2rvNyhHig4/MVoBstxmcB8zwrpiJcFm
         1h2heTJK2/gv4F/mlNIvuAiJ9EPFgB70PO4qZwxYd2waT4z/zXaf35l1hDeutEMTsxsY
         v3FSOO3XE8/akLaAEO+0FoLcBNdEJVX/2ZVhvYy2pLBC9pHADC2gbsmwuYF37EXIkZ93
         d5/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:user-agent:in-reply-to
         :content-disposition:mime-version:references:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=Sa3WKYsapIB90xQKEExASLOUpyuv3HuftCMqh0v2cDo=;
        b=DpbqiA4qEICnN2k6rACIKdAFUaryRTPeHSpaIubC+BqIm5mzQZP2TTRgV5wlNjdD6Y
         Xsp8RVVgZAhUAL2bw/Gm6+9W+7T0d+IY+ibP4Go6odT5IdMh4huQHENLXec85bqqS8q5
         5XCSaP0QgZxUVQT6rtCBTHsIp9kNMCY3XQApS3Nfssw8thRvyWl55F0+hJlwAV11x5hW
         WqbE2phbBGPpBFEBb3nltNp+BfBZEgbDqUzWVeGpnJEg/+ehjcQCeur0uvdFJ78AxjzD
         sowytqbd25meRbTaRTftqikJjUng9X9EwBnjKkrW+gGXWRmaE4187Zm3bEpUkujn4bwl
         0YhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:references:mime-version
         :content-disposition:in-reply-to:user-agent:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sa3WKYsapIB90xQKEExASLOUpyuv3HuftCMqh0v2cDo=;
        b=Khj3jvUGpc0m3oD0ASrWGcrpC21iJIozX51Mf4HI63jtYV0rPZK76unftxIOMCJNJj
         xiokJGPEmIF3wV/4mJUeLgtniKfuB61PILbQs8kU3iJhEMRHhGKt2rI+oSGHKhKwpC3B
         FsxrOnA5BtzFi7Oi0gwO5Wy30HQ8BUFAypWbD1t4PiRHHmICdXJnBqUTGTxwAlppkONW
         p8FnoTWEX/YX7h91XYI9XK0PcmGAqGb7FBScTIlx6YwQKQkBfb19skze8i8tm/P1WRnb
         N+21OBMk3bA2GuhuFP5o/JFfet/mVm92PBVw4gKH9jFbzlwljJ92P80uy2VEaehozVM+
         uWWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:references
         :mime-version:content-disposition:in-reply-to:user-agent:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Sa3WKYsapIB90xQKEExASLOUpyuv3HuftCMqh0v2cDo=;
        b=kOIKl9aRqr2IXzTvDEtfMvx2uvGOMJcZWn6Icyv+Qg8IIHgG9zCemLp/pVj9BlOQoW
         OGiQpO35zL0H19lbuc8wJmAbxIc8g8cusAnMKRqSvP12skG2y0viiObVltgTPACdar+o
         K2hQMN5BtXxh6uZxf/+g/8T+jt8NtZTB9h7eb6BqJtqopymWOCoEF2h+g0bT+Ikj6IVQ
         66XCMcFzztf2fNhpaT0qZkcxm1TymysO9wG44M1EMsii+6mw8DNRyJf9Ck49P1bIsMLk
         wtholmqnakKKp/XpazyRHoECh72CyjYREf4CS4qBDtuxgefisby0hoWlma1DWCnwYxbl
         6HeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVKOmaFMV1iqBMuB/Wpu9IXIZicoqNHe0Vsdn1PbyDKGUHBOBGF
	+EAF3l2Vn1Fuk3j8Px2Io4o=
X-Google-Smtp-Source: APXvYqzAiAG1zhrEgFrB8ecG8SHyt80x6IUo4ZJNTSONvQQs9QCe+h1d2dYWCyeh9+fstfMTjQfJVg==
X-Received: by 2002:ab0:30d4:: with SMTP id c20mr463237uam.136.1569656036841;
        Sat, 28 Sep 2019 00:33:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:324a:: with SMTP id y10ls473905uad.8.gmail; Sat, 28 Sep
 2019 00:33:56 -0700 (PDT)
X-Received: by 2002:ab0:e10:: with SMTP id g16mr7205891uak.42.1569656036537;
        Sat, 28 Sep 2019 00:33:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569656036; cv=none;
        d=google.com; s=arc-20160816;
        b=FDEfBVnwrKSNUdORPhg+wk1GakoaqQVS+HGl2fE6h9GDXnHzpgPD6pVHjyE83bVABo
         EuPpadXzjw8T54vHC5483B0hFLgFLxUzs1ad+9S+2o+nvLNIdJ5t7qUHQy/T98ZN02FH
         UtWpeEx+M9pDDAm/CddyMmLwn04agz3R1YrzKCNhU/RPV+HNMhr4Tp/tvSp3Pi3CuJuE
         Dy0YSJKuOMqipat/r2dhSVdGNFTatY5IDMWDGbIthcGSv1sx6qzzTlQ+AhHJfELDzyRp
         qg9K8/waI5kpEpNsFZbFInpWifsOKIA5HcNGks4xIPnBzOB6pRO1ikBVpEn6HtdGUo7V
         y99g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:user-agent:in-reply-to:content-disposition:mime-version
         :references:subject:cc:to:from:date;
        bh=faNkLRVkBs3pY7uD/gVPYBCYWLp1Z7DbOMK6Z83/uzw=;
        b=fkEj5V3vdNZpNm6M2ovT7tLgu5Mfec2F5xrVTKflVqXNr2wNbh15Vb4nQxXvWIGDHd
         nSx45Ge8JhWRPKPeWvOrGb9TSw1ksZjpnapBmfsUa1yoo1TcWWmtMLkhTMGYprZxFQ+H
         FgsfLlx20e01/pDpFm7ybAlBlOmy4T9LZL39iQ7WCYEYL9Ployt4aYOuFL2Cj5t244//
         g4juSv4ZpvWtwvm5MDQbACqX3PB6gZvqUu8YFRAzd3Dv6sgD4GZZXa6GgF6RI4iJqJWH
         frBhfl9uGzY0juyFpUtBwvOCq6YpzM3N1UrPZreLayPpqXYqd8Bw2OP8z1GUtm2+rbGH
         JmUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id p18si301621vsn.1.2019.09.28.00.33.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 28 Sep 2019 00:33:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098393.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.27/8.16.0.27) with SMTP id x8S7Xkfc019341
	for <kasan-dev@googlegroups.com>; Sat, 28 Sep 2019 03:33:55 -0400
Received: from e06smtp04.uk.ibm.com (e06smtp04.uk.ibm.com [195.75.94.100])
	by mx0a-001b2d01.pphosted.com with ESMTP id 2va0dd3b0k-1
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NOT)
	for <kasan-dev@googlegroups.com>; Sat, 28 Sep 2019 03:33:54 -0400
Received: from localhost
	by e06smtp04.uk.ibm.com with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted
	for <kasan-dev@googlegroups.com> from <rppt@linux.ibm.com>;
	Sat, 28 Sep 2019 08:33:52 +0100
Received: from b06cxnps3075.portsmouth.uk.ibm.com (9.149.109.195)
	by e06smtp04.uk.ibm.com (192.168.101.134) with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted;
	(version=TLSv1/SSLv3 cipher=AES256-GCM-SHA384 bits=256/256)
	Sat, 28 Sep 2019 08:33:39 +0100
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id x8S7XdOa53280776
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sat, 28 Sep 2019 07:33:39 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EA026AE051;
	Sat, 28 Sep 2019 07:33:38 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6CE5CAE045;
	Sat, 28 Sep 2019 07:33:34 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.148.204.50])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Sat, 28 Sep 2019 07:33:34 +0000 (GMT)
Date: Sat, 28 Sep 2019 10:33:32 +0300
From: Mike Rapoport <rppt@linux.ibm.com>
To: Adam Ford <aford173@gmail.com>
Cc: Fabio Estevam <festevam@gmail.com>, Rich Felker <dalias@libc.org>,
        linux-ia64@vger.kernel.org, Petr Mladek <pmladek@suse.com>,
        linux-sh@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
        Heiko Carstens <heiko.carstens@de.ibm.com>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        Max Filippov <jcmvbkbc@gmail.com>, Guo Ren <guoren@kernel.org>,
        Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org,
        Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org,
        linux-c6x-dev@linux-c6x.org,
        Yoshinori Sato <ysato@users.sourceforge.jp>,
        Richard Weinberger <richard@nod.at>, x86@kernel.org,
        Russell King <linux@armlinux.org.uk>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Geert Uytterhoeven <geert@linux-m68k.org>,
        Mark Salter <msalter@redhat.com>, Dennis Zhou <dennis@kernel.org>,
        Matt Turner <mattst88@gmail.com>, linux-snps-arc@lists.infradead.org,
        uclinux-h8-devel@lists.sourceforge.jp,
        devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org,
        linux-um@lists.infradead.org,
        The etnaviv authors <etnaviv@lists.freedesktop.org>,
        linux-m68k@lists.linux-m68k.org, Rob Herring <robh+dt@kernel.org>,
        Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org,
        Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>,
        arm-soc <linux-arm-kernel@lists.infradead.org>,
        Michal Simek <monstr@monstr.eu>, Tony Luck <tony.luck@intel.com>,
        Linux Memory Management List <linux-mm@kvack.org>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        USB list <linux-usb@vger.kernel.org>, linux-mips@vger.kernel.org,
        Paul Burton <paul.burton@mips.com>, Vineet Gupta <vgupta@synopsys.com>,
        linux-alpha@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
        linuxppc-dev@lists.ozlabs.org, "David S. Miller" <davem@davemloft.net>,
        openrisc@lists.librecores.org, Chris Healy <cphealy@gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com>
 <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
 <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
 <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
 <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com>
 <20190926160433.GD32311@linux.ibm.com>
 <CAHCN7xL1sFXDhKUpj04d3eDZNgLA1yGAOqwEeCxedy1Qm-JOfQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHCN7xL1sFXDhKUpj04d3eDZNgLA1yGAOqwEeCxedy1Qm-JOfQ@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-TM-AS-GCONF: 00
x-cbid: 19092807-0016-0000-0000-000002B189F7
X-IBM-AV-DETECTION: SAVI=unused REMOTE=unused XFE=unused
x-cbparentid: 19092807-0017-0000-0000-000033125EFB
Message-Id: <20190928073331.GA5269@linux.ibm.com>
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:,, definitions=2019-09-28_04:,,
 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0
 clxscore=1015 lowpriorityscore=0 mlxscore=0 impostorscore=0
 mlxlogscore=999 adultscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.0.1-1908290000 definitions=main-1909280079
X-Original-Sender: rppt@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=rppt@linux.ibm.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, Sep 26, 2019 at 02:35:53PM -0500, Adam Ford wrote:
> On Thu, Sep 26, 2019 at 11:04 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
> >
> > Hi,
> >
> > On Thu, Sep 26, 2019 at 08:09:52AM -0500, Adam Ford wrote:
> > > On Wed, Sep 25, 2019 at 10:17 AM Fabio Estevam <festevam@gmail.com> wrote:
> > > >
> > > > On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:
> > > >
> > > > > I tried cma=256M and noticed the cma dump at the beginning didn't
> > > > > change.  Do we need to setup a reserved-memory node like
> > > > > imx6ul-ccimx6ulsom.dtsi did?
> > > >
> > > > I don't think so.
> > > >
> > > > Were you able to identify what was the exact commit that caused such regression?
> > >
> > > I was able to narrow it down the 92d12f9544b7 ("memblock: refactor
> > > internal allocation functions") that caused the regression with
> > > Etnaviv.
> >
> >
> > Can you please test with this change:
> >
> 
> That appears to have fixed my issue.  I am not sure what the impact
> is, but is this a safe option?

It's not really a fix, I just wanted to see how exactly 92d12f9544b7 ("memblock:
refactor internal allocation functions") broke your setup.

Can you share the dts you are using and the full kernel log?
 
> adam
> 
> > diff --git a/mm/memblock.c b/mm/memblock.c
> > index 7d4f61a..1f5a0eb 100644
> > --- a/mm/memblock.c
> > +++ b/mm/memblock.c
> > @@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
> >                 align = SMP_CACHE_BYTES;
> >         }
> >
> > -       if (end > memblock.current_limit)
> > -               end = memblock.current_limit;
> > -
> >  again:
> >         found = memblock_find_in_range_node(size, align, start, end, nid,
> >                                             flags);
> >
> > > I also noticed that if I create a reserved memory node as was done one
> > > imx6ul-ccimx6ulsom.dtsi the 3D seems to work again, but without it, I
> > > was getting errors regardless of the 'cma=256M' or not.
> > > I don't have a problem using the reserved memory, but I guess I am not
> > > sure what the amount should be.  I know for the video decoding 1080p,
> > > I have historically used cma=128M, but with the 3D also needing some
> > > memory allocation, is that enough or should I use 256M?
> > >
> > > adam
> >
> > --
> > Sincerely yours,
> > Mike.
> >

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190928073331.GA5269%40linux.ibm.com.
