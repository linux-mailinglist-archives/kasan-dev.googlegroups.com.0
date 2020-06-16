Return-Path: <kasan-dev+bncBDIZTUWNWICRBNVNUP3QKGQEFVRBASA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 138BA1FB442
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 16:27:04 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 59sf15707614qvb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 07:27:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592317623; cv=pass;
        d=google.com; s=arc-20160816;
        b=yvbFfmkiJ8aSKlF0cIy6J95BYS/n4HkZDtWmVAh049e1MMqTjErkX0t1EEqXFjh1jI
         hC8237LrOKn+UpcXAQsi8VhDsD5f8ORgZsBJCz7Guaz+kj+aKm1uhUsklHN7LRsJmmJW
         kr9/ZD19xayqKvAnkDL+BVhyiXgdP/j9SuNxw2ZWphmrtMJ2Gv34p550QbUPxrIrfLZN
         D98v6sak/z1FUb4prIlRgcTvp2kHu6f20Xwa+Pmc7zDOduB/UQHHdMYKZ7PuLx8gWnds
         Q65cGxQ506+2w1PRTHngg63XvSf+PJ+VdcCMTLPnzJEsRKfNKZLLpe3ezNb8QXNI3ZYT
         Xk6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=oWdWZ5mQKyQjRdpind5dCLpNvbkHwqcR07k9EWhQt68=;
        b=pFyiFbcKPUDraPFmt4aveT3ANm+AvNZ6uwh6IwJ3Rh1Iu3eBOJuBXzGktlfeRxB8gh
         VvA7pB40u/TGm2q5tR2NsiMh0+8ju37LkL40RYjjjdt3niQLq412z2namDVL6MQnR4QU
         oCNEKrDi6gX0aJoQXl7AU5BfM4bUfabucwzMtf1pSodQJ2VpUx50fSvP7Fm3NHLy6WJC
         LPyH9JmuMHilqqn+M+nG2hI2XheBtiNeFFeQLIN9kxQpAMrbsvZTOm63hmt2Xv/eeeny
         K3PpAnLLqQwGXeB2/FU17CT5mLz57cRZZpkvfR7D0KWEPVIMR2xhAh96RhB4l2ZyzKD0
         XP4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=WvEeJyFm;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oWdWZ5mQKyQjRdpind5dCLpNvbkHwqcR07k9EWhQt68=;
        b=g4RYzluW0YH8C/MFbBDANlyyvdqd2tnpmY8qj5QI6FcC6UlNOVwpnYH2Cm6DV98qjm
         VDr5ZEaF+ERtIQkUeJxQTHp7bi9GMde0IYX3F2bsArX1ADoW8Xeki2XMUkE+MWDVFbnb
         d8rW8e9cRExwAEqPaRapCP2RXBB7MPdiVcAvNoxOTjT6mAVu00nYbFSnZDUmx594nFsr
         Q5rdY4GepwOV/TrXs0HrE3e/LCbAd/SRl1zo3ovY1MV9YbqWNNz4vYoXUJFEFffGWG1J
         Wob7ZrwUFY+9wUjdHZG8flnKtreoK/8qiuTpGO1ZBkID1yT9Wx91RwHnBUeCWbF1iiC5
         X1cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oWdWZ5mQKyQjRdpind5dCLpNvbkHwqcR07k9EWhQt68=;
        b=j2KlpPZCZjM79A+iEDav8u+yPFKIhFTC4MWefLYMpCYD8rh+uY0kAajSrbk3fSKxxC
         Vzk1JOkTXf6AoRee5u0M8uuZcyoAZzy7cIK+fkz39ARhCuTgjL8pwIfbX+1q5esHpzuS
         jJwj/mwRgu1EkGrjmAq6Ct0et6CarS4FmBuYRIo2z0i3XsafKqcS0fqfns3KP0C9llqq
         AHz7q4JYTkpziGCSN35m5Y47JamjL2DyDRskMDfHBNeDHRPWxsCUgYD7Ev14/Jng1EIe
         LuhrbeX+0z2SZrLLZXh/+xtB4InY0wQ6go43SpHkC60KatqimOSYPyetD4PcChNnzjLO
         p+Dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PigcB3+QrVFeU60I0B+9hvNLDj5YILkVvmPibMuyC7moGQo+r
	wlNi5/A4W0/UfwjoNJJi9bU=
X-Google-Smtp-Source: ABdhPJydgFzbL0gkq3Cj2Nd6ruXfor/rsJdC4Z72vntl+qtGn9uoilmMy2moja8+9FOuzE0uR0wddg==
X-Received: by 2002:aed:3344:: with SMTP id u62mr21197251qtd.174.1592317622865;
        Tue, 16 Jun 2020 07:27:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:78d:: with SMTP id 135ls8344769qkh.8.gmail; Tue, 16 Jun
 2020 07:27:02 -0700 (PDT)
X-Received: by 2002:a05:620a:753:: with SMTP id i19mr21187303qki.357.1592317622409;
        Tue, 16 Jun 2020 07:27:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592317622; cv=none;
        d=google.com; s=arc-20160816;
        b=WCYsFdNR2ZxgHDAr7TU0uico8kIRUx+1vLHfovNv2Yq95XcrwcnYV/YKhp2YDvGs71
         l+i51+4OlL4VPhbqayIYwpU3FsA+aTMVpaIe2TEX9nNI5r2wzxH5Wqq9N5pET+bXp1f3
         wrDo+zO32HMldiqdgne3oWakwXglGWLj12diwDK1vk9iztMQP/UZQXBmH5wG2ccFQo/P
         bKe7UbUPriqKaFZFFjmaeXLdVbAhKEQTjE2gzKds5Mtgyqs5DKo/0aEQbhYJdNkHMvYf
         iNRFRB1uhCo8o3zrD32CL3zze3D1QDSf5jnA7IFGlX4gywfIiBM2h5Oj3oXRv+EPORvB
         qmYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UepsmQC/DlQFZ6+UxfaNjoC9RmBOSxOKZ2W1AkmRQd8=;
        b=fYeqcjKJpX2+bmlR+8SFWlYC5c6eoQqEYv1di/SXKdciDpM0dJZlciiE9ttYf01dtH
         7572LbXQVN0XfuM++CEU2bSTnTBEUmQjplYPAOMj1HKCMJ8KOVxsaNMekWFVqwDCgU7c
         uMYgWESLCF6Cpmsw1Htp4HeXBGbMokDM+6lAy9YXshsR0LKyBpqtOvMTiYVflNHOLXu7
         K1rQSEAs+pWBI2/MvlDsu0zf0aXkJptxz7UXtYCX3TrQMNIMT+lnk4eGCHpdyIsGcrGr
         yyVmf72NJ8XkQakcQKq4IQaun1ak2N/sbYLGeMszEImfW3Nv9c+k+eCsRjzZu86quBQq
         AELA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=WvEeJyFm;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id d3si739736qtg.0.2020.06.16.07.27.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 07:27:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.carpenter@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 05GELOZQ057447;
	Tue, 16 Jun 2020 14:26:56 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by userp2120.oracle.com with ESMTP id 31p6e5y3y1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=FAIL);
	Tue, 16 Jun 2020 14:26:56 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 05GEODoW027404;
	Tue, 16 Jun 2020 14:26:56 GMT
Received: from aserv0122.oracle.com (aserv0122.oracle.com [141.146.126.236])
	by userp3030.oracle.com with ESMTP id 31p6s7kbhq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 16 Jun 2020 14:26:56 +0000
Received: from abhmp0017.oracle.com (abhmp0017.oracle.com [141.146.116.23])
	by aserv0122.oracle.com (8.14.4/8.14.4) with ESMTP id 05GEQfNL026862;
	Tue, 16 Jun 2020 14:26:42 GMT
Received: from kadam (/41.57.98.10)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Tue, 16 Jun 2020 07:26:41 -0700
Date: Tue, 16 Jun 2020 17:26:24 +0300
From: Dan Carpenter <dan.carpenter@oracle.com>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        David Howells <dhowells@redhat.com>,
        Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
        James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
        David Rientjes <rientjes@google.com>, Michal Hocko <mhocko@suse.com>,
        Johannes Weiner <hannes@cmpxchg.org>, David Sterba <dsterba@suse.cz>,
        "Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
        keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
        linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
        linux-stm32@st-md-mailman.stormreply.com,
        linux-amlogic@lists.infradead.org, linux-mediatek@lists.infradead.org,
        linuxppc-dev@lists.ozlabs.org,
        virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
        linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
        linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
        linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
        linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
        linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
        kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
        linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
        linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
        linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
Subject: Re: [PATCH v4 2/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200616142624.GO4282@kadam>
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-3-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200616015718.7812-3-longman@redhat.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9653 signatures=668680
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 suspectscore=0
 mlxlogscore=886 adultscore=0 phishscore=0 bulkscore=0 spamscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2004280000 definitions=main-2006160106
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9653 signatures=668680
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 priorityscore=1501 adultscore=0
 mlxscore=0 phishscore=0 mlxlogscore=893 lowpriorityscore=0 clxscore=1011
 suspectscore=0 spamscore=0 bulkscore=0 malwarescore=0 impostorscore=0
 cotscore=-2147483648 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2004280000 definitions=main-2006160106
X-Original-Sender: dan.carpenter@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=WvEeJyFm;
       spf=pass (google.com: domain of dan.carpenter@oracle.com designates
 156.151.31.85 as permitted sender) smtp.mailfrom=dan.carpenter@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

Last time you sent this we couldn't decide which tree it should go
through.  Either the crypto tree or through Andrew seems like the right
thing to me.

Also the other issue is that it risks breaking things if people add
new kzfree() instances while we are doing the transition.  Could you
just add a "#define kzfree kfree_sensitive" so that things continue to
compile and we can remove it in the next kernel release?

regards,
dan carpenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616142624.GO4282%40kadam.
