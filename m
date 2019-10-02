Return-Path: <kasan-dev+bncBAABBA5H2HWAKGQEADMYIVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B42DC489B
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 09:36:37 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id q5sf9218595vkg.20
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 00:36:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570001795; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpPSguKBd5vDD7dYMnNuvvHjmk7CrcKsumilMP7WkMk/uvDYA6iiUdhBTDpwBMuRrx
         UychG/IZaupV+UX1Oqhdt+3QBqW+J/nzz6CmynVn9vDMPmj38SR53Lgk+AfVtMOxqiee
         q91/iukLEuBSYvLE13o9EVIBspCNqeBqibN9JlvYrY7BWInRiG2B7vKkq9nRHGPrbam1
         fHLa1qB0r2rtEoR6hWDaWN7ffyRJlaAXFMLSCRTH5ZhyXsub2QVLmRyyfXNkXZO03Rsh
         epsSFioVWm4TObgakdrJAvzw8/tBr8OUBS8sPcl6BS0NVz4ube+dLBHQnLvtci6+JqGJ
         lYeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:user-agent:in-reply-to
         :content-disposition:mime-version:references:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=SofUJycZ2S08kiToS4/S85Skca7kM5lK44xGzgdhfQg=;
        b=PeBnWh13tXeQGIyZNMFZAOH1VKbtcHAi1KM4gUvhIBa2QB7nXDHVyEpO1E5IHCnMBP
         kV1p33j3AjJcj1xctgOXGBAqRMNzFjIsRnLj86476/dSdHB+2kDhJGHQkrXL1KYNaQRQ
         mVcnWFeKk1av2h6gqN8OOeRDxsJpU6Y+IZj1nv7cmONaJ0vmQZzN3TOAw2ytSb2Pt1rA
         GPWB4fp2rlDtwlc5OoilS2FUB43dzgoqDhWjmZBSKO9hkIbsJgy0VyWHATHWW2v1PJWG
         +e6H1H3PhCoXFh4jeIodr3TKnd2XA3vL6ToKk4qRPhqv7rcSIOAERCCinPQUnF9blICq
         8afA==
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
        bh=SofUJycZ2S08kiToS4/S85Skca7kM5lK44xGzgdhfQg=;
        b=cTHThrHCUAQHvtq+tvVuVezZUNkF19bPVLwzf0n02O+quAoN3txcUQc5vJ69j63OKZ
         DlRi/wic800OmiX+kEa8kokiGjYcL7s4KCiG41ZNLklnzqq+icfCoJToFVQHdWApAQsP
         2C5SOd3PQGX1MRoF/Yg0YQFNszt5AeYY6/rSXYne7VCfTrsgflxGpuXdkhYPJyiSuSno
         H5jpJ6OWSZ9DB2yJGMdSRn2ebPy9WVy/L+As9jd0b/DhFEMag1nGdB0rsG4ZLvrHzbX1
         D/P3chWHZuGWHmMuQqMaZvuPnd2XbXmWEkmFAeqf81nO20z1TTBIl821AMlQMkkO8YuH
         UWCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:references
         :mime-version:content-disposition:in-reply-to:user-agent:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SofUJycZ2S08kiToS4/S85Skca7kM5lK44xGzgdhfQg=;
        b=jhnRHzp+PjQh57/S16M8oe3X0oKKTtpg3/4kiGnRYNEBmTQS28dUnrHAKXIAS/NT4M
         w3G2lfbuxX1qNw2oPFJznqNVzhnA+2l7xA7LIBxFxtR35feHk5WiMA870jaa4luHcASX
         nG2hNqMJedCJ7/PpO1ohXBAqw6ZZQSm3lholxap2KBBMrjfmKFm5BM0T4rkdqOrkBrfb
         0VU5VWhBVpwOQuTfQLgBx+88JECtFrC3XT9UdIixcuJw2CqGZzagvUGu/0wyTox2Iy34
         2w/iaHEozcLVuiyrwf0EL47KlFoXusQnd6U0wI1BuFCcJyv4hyrd0fB9NWbprYu7f1Eo
         mIaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVdGDluiZHmDYBD5qOdoH8pQkCBtyEYIYbrARj5GmqybsyRdnzR
	AwL8Sod9gw22wfBqM1HCW/8=
X-Google-Smtp-Source: APXvYqx9LPIrFg711k6kf8nDCBxn4zekFzHKXKodWPDUWfwqq0pRZTozOsLeMc0NuPhbyDx/21UJAA==
X-Received: by 2002:a67:dc13:: with SMTP id x19mr1037315vsj.172.1570001795788;
        Wed, 02 Oct 2019 00:36:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:efd2:: with SMTP id s18ls148515vsp.6.gmail; Wed, 02 Oct
 2019 00:36:35 -0700 (PDT)
X-Received: by 2002:a67:fd6a:: with SMTP id h10mr1073443vsa.146.1570001795474;
        Wed, 02 Oct 2019 00:36:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570001795; cv=none;
        d=google.com; s=arc-20160816;
        b=No4k15DBHJgEIG520+hIa8piCujiseiJC1U/Ay0XuXwT8Z0jgYP/6+VsPvhtJtQtiC
         3L8XL0TtiFlnkXVyg91x8sXDmefsGQuekoqw0DyBas0CUwAY2gTOvAw3GrahBpNOY5Gn
         EbMhxvieDgongZb9NHe3+Dd0MQoc4zrrXmlI1yxKnOZQd45t6e+ipT5npNwM0Dlb9Gcg
         uv/Q6oMgtTPUpu4WgxedTDx1+y01jyI7CME5IkhDaDLIqYjZx1Qew9nmJS+qt/CvCJ7F
         R9FA48aYr2cq8wE6qOvGGCD3ggsxYHrNZ6hi5Vod1KFEEPCW+fgzl8tO4OPjcIymlSCU
         z2Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:user-agent:in-reply-to:content-disposition:mime-version
         :references:subject:cc:to:from:date;
        bh=AafcdW3urFkd6FqsJzHqaS0U7VkMVuJk+iwZOEozTpA=;
        b=WAaA4D9p30pkQzVT/HFmnFAoGyMVcv+c2jtDxPAIdlfFHnHFt9Ef+MrBrtoZsNHNZB
         yqtrkL7+nxTsCwZeKJKbR6v8rgLSe0ERl889RraafW164XUNdxRLLMym0ZQUg0xvC8X6
         u4u12dAxs4ocClK4OOmdXsrhxW2FJnaYD0KBoncH3mN57q/o21oc/JcqzbIcd2KKf1w/
         SRXfqVYjjog1WSAPEtAXdjKQG3J5WF5Gf8J1MAxoTg+HRXdRGjGPyISkU33B+Z9gpT6v
         KrlwPtaXr8aHjVwr0LqTzlNKCQLRGmGrhmLv3J6RDnuKLNcDiJmZ0Z9a9yzp0XSjpeDb
         qiYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rppt@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id p18si926925vsn.1.2019.10.02.00.36.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Oct 2019 00:36:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098404.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.27/8.16.0.27) with SMTP id x927aWax053763
	for <kasan-dev@googlegroups.com>; Wed, 2 Oct 2019 03:36:34 -0400
Received: from e06smtp02.uk.ibm.com (e06smtp02.uk.ibm.com [195.75.94.98])
	by mx0a-001b2d01.pphosted.com with ESMTP id 2vckrne6t0-1
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NOT)
	for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 03:36:33 -0400
Received: from localhost
	by e06smtp02.uk.ibm.com with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted
	for <kasan-dev@googlegroups.com> from <rppt@linux.ibm.com>;
	Wed, 2 Oct 2019 08:36:23 +0100
Received: from b06avi18626390.portsmouth.uk.ibm.com (9.149.26.192)
	by e06smtp02.uk.ibm.com (192.168.101.132) with IBM ESMTP SMTP Gateway: Authorized Use Only! Violators will be prosecuted;
	(version=TLSv1/SSLv3 cipher=AES256-GCM-SHA384 bits=256/256)
	Wed, 2 Oct 2019 08:36:12 +0100
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (b06wcsmtp001.portsmouth.uk.ibm.com [9.149.105.160])
	by b06avi18626390.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id x927ZgPA34865576
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 2 Oct 2019 07:35:42 GMT
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 56E0EA4060;
	Wed,  2 Oct 2019 07:36:11 +0000 (GMT)
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CDD2EA4054;
	Wed,  2 Oct 2019 07:36:07 +0000 (GMT)
Received: from linux.ibm.com (unknown [9.148.8.153])
	by b06wcsmtp001.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Wed,  2 Oct 2019 07:36:07 +0000 (GMT)
Date: Wed, 2 Oct 2019 10:36:06 +0300
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
References: <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
 <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
 <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
 <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com>
 <20190926160433.GD32311@linux.ibm.com>
 <CAHCN7xL1sFXDhKUpj04d3eDZNgLA1yGAOqwEeCxedy1Qm-JOfQ@mail.gmail.com>
 <20190928073331.GA5269@linux.ibm.com>
 <CAHCN7xJEvS2Si=M+BYtz+kY0M4NxmqDjiX9Nwq6_3GGBh3yg=w@mail.gmail.com>
 <CAHCN7xKLhWw4P9-sZKXQcfSfh2r3J_+rLxuxACW0UVgimCzyVw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHCN7xKLhWw4P9-sZKXQcfSfh2r3J_+rLxuxACW0UVgimCzyVw@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-TM-AS-GCONF: 00
x-cbid: 19100207-0008-0000-0000-0000031D3BD8
X-IBM-AV-DETECTION: SAVI=unused REMOTE=unused XFE=unused
x-cbparentid: 19100207-0009-0000-0000-00004A3C3DD3
Message-Id: <20191002073605.GA30433@linux.ibm.com>
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:,, definitions=2019-10-02_04:,,
 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0
 clxscore=1015 lowpriorityscore=0 mlxscore=0 impostorscore=0
 mlxlogscore=999 adultscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.0.1-1908290000 definitions=main-1910020071
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

Hi Adam,

On Tue, Oct 01, 2019 at 07:14:13PM -0500, Adam Ford wrote:
> On Sun, Sep 29, 2019 at 8:33 AM Adam Ford <aford173@gmail.com> wrote:
> >
> > I am attaching two logs.  I now the mailing lists will be unhappy, but
> >  don't want to try and spam a bunch of log through the mailing liast.
> > The two logs show the differences between the working and non-working
> > imx6q 3D accelerator when trying to run a simple glmark2-es2-drm demo.
> >
> > The only change between them is the 2 line code change you suggested.
> >
> > In both cases, I have cma=128M set in my bootargs.  Historically this
> > has been sufficient, but cma=256M has not made a difference.
> >
> 
> Mike any suggestions on how to move forward?
> I was hoping to get the fixes tested and pushed before 5.4 is released
> if at all possible

I have a fix (below) that kinda restores the original behaviour, but I
still would like to double check to make sure it's not a band aid and I
haven't missed the actual root cause.

Can you please send me your device tree definition and the output of 

cat /sys/kernel/debug/memblock/memory

and 

cat /sys/kernel/debug/memblock/reserved

Thanks!

From 06529f861772b7dea2912fc2245debe4690139b8 Mon Sep 17 00:00:00 2001
From: Mike Rapoport <rppt@linux.ibm.com>
Date: Wed, 2 Oct 2019 10:14:17 +0300
Subject: [PATCH] mm: memblock: do not enforce current limit for memblock_phys*
 family

Until commit 92d12f9544b7 ("memblock: refactor internal allocation
functions") the maximal address for memblock allocations was forced to
memblock.current_limit only for the allocation functions returning virtual
address. The changes introduced by that commit moved the limit enforcement
into the allocation core and as a result the allocation functions returning
physical address also started to limit allocations to
memblock.current_limit.

This caused breakage of etnaviv GPU driver:

[    3.682347] etnaviv etnaviv: bound 130000.gpu (ops gpu_ops)
[    3.688669] etnaviv etnaviv: bound 134000.gpu (ops gpu_ops)
[    3.695099] etnaviv etnaviv: bound 2204000.gpu (ops gpu_ops)
[    3.700800] etnaviv-gpu 130000.gpu: model: GC2000, revision: 5108
[    3.723013] etnaviv-gpu 130000.gpu: command buffer outside valid
memory window
[    3.731308] etnaviv-gpu 134000.gpu: model: GC320, revision: 5007
[    3.752437] etnaviv-gpu 134000.gpu: command buffer outside valid
memory window
[    3.760583] etnaviv-gpu 2204000.gpu: model: GC355, revision: 1215
[    3.766766] etnaviv-gpu 2204000.gpu: Ignoring GPU with VG and FE2.0

Restore the behaviour of memblock_phys* family so that these functions will
not enforce memblock.current_limit.

Fixes: 92d12f9544b7 ("memblock: refactor internal allocation functions")
Reported-by: Adam Ford <aford173@gmail.com>
Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
---
 mm/memblock.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/memblock.c b/mm/memblock.c
index 7d4f61a..c4b16ca 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
 		align = SMP_CACHE_BYTES;
 	}
 
-	if (end > memblock.current_limit)
-		end = memblock.current_limit;
-
 again:
 	found = memblock_find_in_range_node(size, align, start, end, nid,
 					    flags);
@@ -1469,6 +1466,9 @@ static void * __init memblock_alloc_internal(
 	if (WARN_ON_ONCE(slab_is_available()))
 		return kzalloc_node(size, GFP_NOWAIT, nid);
 
+	if (max_addr > memblock.current_limit)
+		max_addr = memblock.current_limit;
+
 	alloc = memblock_alloc_range_nid(size, align, min_addr, max_addr, nid);
 
 	/* retry allocation without lower limit */
-- 
2.7.4

 
> > adam
> >
> > On Sat, Sep 28, 2019 at 2:33 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
> > >
> > > On Thu, Sep 26, 2019 at 02:35:53PM -0500, Adam Ford wrote:
> > > > On Thu, Sep 26, 2019 at 11:04 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
> > > > >
> > > > > Hi,
> > > > >
> > > > > On Thu, Sep 26, 2019 at 08:09:52AM -0500, Adam Ford wrote:
> > > > > > On Wed, Sep 25, 2019 at 10:17 AM Fabio Estevam <festevam@gmail.com> wrote:
> > > > > > >
> > > > > > > On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:
> > > > > > >
> > > > > > > > I tried cma=256M and noticed the cma dump at the beginning didn't
> > > > > > > > change.  Do we need to setup a reserved-memory node like
> > > > > > > > imx6ul-ccimx6ulsom.dtsi did?
> > > > > > >
> > > > > > > I don't think so.
> > > > > > >
> > > > > > > Were you able to identify what was the exact commit that caused such regression?
> > > > > >
> > > > > > I was able to narrow it down the 92d12f9544b7 ("memblock: refactor
> > > > > > internal allocation functions") that caused the regression with
> > > > > > Etnaviv.
> > > > >
> > > > >
> > > > > Can you please test with this change:
> > > > >
> > > >
> > > > That appears to have fixed my issue.  I am not sure what the impact
> > > > is, but is this a safe option?
> > >
> > > It's not really a fix, I just wanted to see how exactly 92d12f9544b7 ("memblock:
> > > refactor internal allocation functions") broke your setup.
> > >
> > > Can you share the dts you are using and the full kernel log?
> > >
> > > > adam
> > > >
> > > > > diff --git a/mm/memblock.c b/mm/memblock.c
> > > > > index 7d4f61a..1f5a0eb 100644
> > > > > --- a/mm/memblock.c
> > > > > +++ b/mm/memblock.c
> > > > > @@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
> > > > >                 align = SMP_CACHE_BYTES;
> > > > >         }
> > > > >
> > > > > -       if (end > memblock.current_limit)
> > > > > -               end = memblock.current_limit;
> > > > > -
> > > > >  again:
> > > > >         found = memblock_find_in_range_node(size, align, start, end, nid,
> > > > >                                             flags);
> > > > >
> > > > > > I also noticed that if I create a reserved memory node as was done one
> > > > > > imx6ul-ccimx6ulsom.dtsi the 3D seems to work again, but without it, I
> > > > > > was getting errors regardless of the 'cma=256M' or not.
> > > > > > I don't have a problem using the reserved memory, but I guess I am not
> > > > > > sure what the amount should be.  I know for the video decoding 1080p,
> > > > > > I have historically used cma=128M, but with the 3D also needing some
> > > > > > memory allocation, is that enough or should I use 256M?
> > > > > >
> > > > > > adam
> > > > >
> > > > > --
> > > > > Sincerely yours,
> > > > > Mike.
> > > > >
> > >
> > > --
> > > Sincerely yours,
> > > Mike.
> > >

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191002073605.GA30433%40linux.ibm.com.
