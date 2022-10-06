Return-Path: <kasan-dev+bncBCUO3AHUWUIRB6VJ7OMQMGQELMDEN7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 685CD5F677D
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:15:39 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id mo5-20020a056214330500b004ad711537a6sf1076851qvb.10
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:15:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665062138; cv=pass;
        d=google.com; s=arc-20160816;
        b=bnfGRsdSaaFk5y5tSFTlvTcQ/IXoPL+bLeCod9Nt80c4XlqSmYFnBqBRk0jb6EW+ro
         Gc+P4UKQij/i6SDUTvPtFmpqoGE1+4Ln+UR67VA2T1AhZR9dSccneSqTrGJeoOr3K/kV
         43SFllAEvMRiaBC8r2Q5JwQHgu7bH5ZKK7109ZptNPaL7Qf6VXyoppRn3e6F1ulj4T/y
         iQANoApwxDr6d6lyRtOJtaDHHV7FcL25tunta1oxUdIEvYtBBZuQ1JEROA0EWcSCpCNC
         SuNTetFPKpoEjHg+PzbqIOSe5bDbscoAQSFeWn77E0OjWaFl/IciSJTMaA/TTkCYi5IY
         XGbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RT6LiT7up8t9EBFYXfMryRRT0qMprdxnzALCEMv459s=;
        b=RYgPwaDEMv59nZ8TtuVSdU6CJzhaDSGe+JWmxUJKUkaYlj5KUhImAj0hCbF7/tYFWt
         JB9P+jQcA1Xd+f5BX8f4RgH+Ad3AFiv+/9jkZiPSNFaDAxYyCcs6ilyKTbpr/o5n6l4Q
         Om7Zb+J1dFj0HhTEsA3OWVgdWZQpOP1RlL6tR6vyVTWeD9x/SgbZrLvWtcCGivAir1BJ
         xTrVtdjksH+mXTOmD5nHpwccTSuKbcwceAi7xp6AcIRmFGGlYfa8fp9lUnJd8INbYChG
         J0Ef8EQfVhl/xB+wncefcEmKI9f4ROHcnhRoxyeqjjzOQO/9KeoaUKp5oZJNvLQw5LpL
         WZJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=j4TXfdYh;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=RT6LiT7up8t9EBFYXfMryRRT0qMprdxnzALCEMv459s=;
        b=ZiUT7Orgq4p5ir73S2QgqVUhkKknTrRKfR7jrwMcEMc0ZCbiJzkcJIkPuTGaoibhKe
         cS6MvYQ7ToZw08aQsqRaddzAzFuYMAEilTvI3lXLjNAe/LT+UUg7h89Wr7fAw1ZN4Rk6
         T6tjluqQuDXEVNLbRG19DlYirKNiBzQXvCsicOam5gGRwKsvwzBZuYPqsHLDNPEb8Xri
         KBYn4drJkIBRifszZN1t1eoCiCPVhee3bh5uAu0zBIOqkXN5B++oQgn6W9UeslHOThcy
         B25DzeF6TClicUrPRpkwfs6S6JBo+fCrpnPcJl/fPMwd6U73aDc/3oCJivc1/XR2nQdz
         SmwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=RT6LiT7up8t9EBFYXfMryRRT0qMprdxnzALCEMv459s=;
        b=QJHQ6PiHCcfihmCMWQvjj5y13WSowRZi+DUDQuk+oy0qa2U9Pmaq71X7ddfhYwRxBn
         cEhaDSdBzjSASvoLDgo2v9/+is1AktZ+dubh0cx7jzX9xURV5RKytB26URks77eJNFr8
         QBITEeYBIre19OTqKziGpWfwCD6oTpul8EIjGDe6XZZFi8kh7kTAInPd4xh2kVEbODq4
         Nb1NC9GKpB3xpmzJpNMC63pTmDoqBX7zRs+oLslBKzhA0dSBjZvWR0ZYF/a9gZqfMq1l
         L6YfEV7KYNCVREFtt4Tj4FFplvFqr7xBB/QqNfudBlCK9aPZLOC6fMG8wINCrxs8jLQj
         Hv4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1/7xYluukEt9MK9RBLjZ5PaJM7kaZnsSLPI/ueYWnXR3K86qmj
	67IqJqc+VV4bsb21U40rXHs=
X-Google-Smtp-Source: AMsMyM7Ou3vwBXcf3N90YQTAq+JVi6tllAedEshTFu5lGQWvjTEerEzTRKWo8tLxPQqDhL5YPNTQ+w==
X-Received: by 2002:a05:620a:258f:b0:6cf:663b:9751 with SMTP id x15-20020a05620a258f00b006cf663b9751mr3052715qko.367.1665062138109;
        Thu, 06 Oct 2022 06:15:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b31d:0:b0:4af:b19a:9b5d with SMTP id s29-20020a0cb31d000000b004afb19a9b5dls988217qve.6.-pod-prod-gmail;
 Thu, 06 Oct 2022 06:15:37 -0700 (PDT)
X-Received: by 2002:a0c:a79a:0:b0:4b1:ca99:177 with SMTP id v26-20020a0ca79a000000b004b1ca990177mr3849401qva.34.1665062137649;
        Thu, 06 Oct 2022 06:15:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665062137; cv=none;
        d=google.com; s=arc-20160816;
        b=IjnUWlneOvsHqWjGVOfuU3Pk6l81zrVEazQgiOD7GVq5q1/wEDpZaP1xfUYTFcUXe8
         Knyu8JKV4f06j1z/n+1c8m4+ARYXZbEnP/XOMsgb8Eb36Lm59Y5VQXZEBPjgp912WB76
         dXK82KgSa63LWzzKAgHNSLX7i1IbpoZj0/qeipaEmLpxlhZqOxM6yHHPxR5uK8As+DUC
         0slADbArngsxZrsDOrEzyw9wiG+TybqqNEfeJKrF03ey0V1qEfCoYQ3NeBxsdaAMyFZd
         7d3gJHxUTr4QEcjt9GgWSuy08JPTT7CLBiX4e3xxavFqGAMbZZITz7sA66Mavck8wmrj
         XMRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GSOPunDdTF0UIVvBpION9xBpexDiGo+rjOxipFbXtOA=;
        b=suNVA+X0yTq6XZHfT2ZpY5jYVSmSofK7peI/40BALSNagrBO30c+Ecl85HC2kjodfd
         1JMAtvyTxCqW9lPUF36L++nimSvfx3hzTMFFCMLWI95pvh1NLQKjXuVOViInAhSdI2WK
         4XWQpRl3RttFPwjQ5aAK2qR2BqUdXcgo/feW840zW3dxyT8zll3cW5TNd0dm2IcONBAJ
         qDtCwz7sm+cPLuOrpdcwYv0DRkXLGy1Pfc2VR+1q8Rmat6zbD2LhEPo/l804eVaI4bpI
         iQS/HhCwUg6LSNMj7MH7SZQMinZoxqMrcLzXkJpl+BPqSclJhM1XPUHvK6q7skf5shQS
         Y5WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=j4TXfdYh;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id b18-20020a05620a089200b006e6046e7c55si41729qka.5.2022.10.06.06.15.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:15:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id s21so916985qtx.6
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 06:15:37 -0700 (PDT)
X-Received: by 2002:ac8:5703:0:b0:35c:c3f6:5991 with SMTP id 3-20020ac85703000000b0035cc3f65991mr3383265qtw.185.1665062137334;
        Thu, 06 Oct 2022 06:15:37 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-47-55-122-23.dhcp-dynamic.fibreop.ns.bellaliant.net. [47.55.122.23])
        by smtp.gmail.com with ESMTPSA id k11-20020a05620a0b8b00b006cbc6e1478csm18686320qkh.57.2022.10.06.06.15.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 06:15:36 -0700 (PDT)
Received: from jgg by wakko with local (Exim 4.95)
	(envelope-from <jgg@ziepe.ca>)
	id 1ogQit-00A1hY-6O;
	Thu, 06 Oct 2022 10:15:35 -0300
Date: Thu, 6 Oct 2022 10:15:35 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, brcm80211-dev-list.pdl@broadcom.com,
	cake@lists.bufferbloat.net, ceph-devel@vger.kernel.org,
	coreteam@netfilter.org, dccp@vger.kernel.org, dev@openvswitch.org,
	dmaengine@vger.kernel.org, drbd-dev@lists.linbit.com,
	dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com,
	linux-actions@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-ext4@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
	linux-fbdev@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-hams@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mm@kvack.org, linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org, linux-nfs@vger.kernel.org,
	linux-nvme@lists.infradead.org, linux-raid@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-scsi@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linux-xfs@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, lvs-devel@vger.kernel.org,
	netdev@vger.kernel.org, netfilter-devel@vger.kernel.org,
	rds-devel@oss.oracle.com, SHA-cyfmac-dev-list@infineon.com,
	target-devel@vger.kernel.org, tipc-discussion@lists.sourceforge.net
Subject: Re: [PATCH v1 3/5] treewide: use get_random_u32() when possible
Message-ID: <Yz7U99PPl8uHCLFY@ziepe.ca>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-4-Jason@zx2c4.com>
 <Yz7OdfKZeGkpZSKb@ziepe.ca>
 <CAHmME9r_vNRFFjUvqx8QkBddg_kQU=FMgpk9TqOVZdvX6zXHNg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHmME9r_vNRFFjUvqx8QkBddg_kQU=FMgpk9TqOVZdvX6zXHNg@mail.gmail.com>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=j4TXfdYh;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::829 as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca
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

On Thu, Oct 06, 2022 at 07:05:48AM -0600, Jason A. Donenfeld wrote:

> > > diff --git a/drivers/infiniband/ulp/ipoib/ipoib_cm.c b/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> > > index fd9d7f2c4d64..a605cf66b83e 100644
> > > --- a/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> > > +++ b/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> > > @@ -465,7 +465,7 @@ static int ipoib_cm_req_handler(struct ib_cm_id *cm_id,
> > >               goto err_qp;
> > >       }
> > >
> > > -     psn = prandom_u32() & 0xffffff;
> > > +     psn = get_random_u32() & 0xffffff;
> >
> >  prandom_max(0xffffff + 1)
> 
> That'd work, but again it's not more clear. Authors here are going for
> a 24-bit number, and masking seems like a clear way to express that.

vs just asking directly for a 24 bit number?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7U99PPl8uHCLFY%40ziepe.ca.
