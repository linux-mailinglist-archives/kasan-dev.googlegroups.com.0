Return-Path: <kasan-dev+bncBDUNBGN3R4KRBWWHWOPAMGQE3UJOAGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 16649676B73
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Jan 2023 08:20:59 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id d14-20020a196b0e000000b004b562e4bfedsf3758433lfa.19
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 23:20:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674372058; cv=pass;
        d=google.com; s=arc-20160816;
        b=zcew0slHcRu/tuHjkL4kdT4ve+kE7X6kpD4WNFbkVfa33qnRrkl21d1Jsw8qGa0yBJ
         8CbwGDXRGhOIRLgGMuKJF+CmRRRzddE2YwEIuw8Ip6jNfbSovexMbDnQHNCpk1wb+xM8
         qHaFykwiIAamff4Tjk8rjoAg9W0T8Di1l7qT4X4zBWn0XfiwkhklTlCoS4rEx4ARL68p
         qgi/vTkDcENQb0NEfGcs4IVUIraw1Vi3Tl0BpGRodjnE/J8+hLc8jnhjQ1VUS5vNFmxV
         2i/iE30qYyceHUFGHQ6ARudooZpedAMgKQtFxT+a07mducXT/F2SlJ06ApXrwN5YAobE
         IXLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ibEhrb2DFYRR8iojEmNHj1TYZcBya3sd5+O6knbSMPc=;
        b=1CGndpk4rSVHqKCN6yqAuHKXIR6qshaLEajlnEUfFJ1nxtWsWD6vcQ88vg8ROnJY14
         7x5dKgP59+ftUO/WHKbh5cl0/Jk3qTXDfgmxTawazAp8cpYDsNxN+BezJLVvblRasv++
         T/hx9fu8daSKuTsIH18ekEOhTR3mQBwF3v4ih09ar4H33cxHTToCfDnO453sRfSbCpnG
         G2OSqRDTZJ4Cv//tXKY6815GreHagCuTfCFdAkBDueOU3voBPExcu+0SjehwEkKree0o
         vq1kFnbQZsLVw4gbNN3Fz6wI6d4b+p8mOEpCiBKHXyDVKAvQYrvgxjKbDjbwvHakZfPA
         hFfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ibEhrb2DFYRR8iojEmNHj1TYZcBya3sd5+O6knbSMPc=;
        b=nZuO7ObjyQaS9BGx1juhDkKWymEqFg/wUE+1uxplQZXksQdISN5LBiBvUC4P6Gvfog
         Kz5WHRCcqwS03ZvQmYDzhfalKIwbYAbjaqeVQXdlokRyhtu6wqC+I02mjXVGwV4ZtaHP
         elQI3h07UXBe4y67IZYqO+MGxEM4ZNQWcx/7TY372GN+s7Q85ISogNproMDZnl3tk2r4
         6pCZCPkgtqeXsA1TmwlLphFKS4ThkQm6bAwGq23pQ9wrIffeAKz+Q5iKitB3NMqYg9Me
         VkMXf9PYhPuhvnSZJN9HN9hCSk9YgdMp73Ssrd7hv03PZF3LnHpYoYoA8/BDO8m14Yzp
         BMMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ibEhrb2DFYRR8iojEmNHj1TYZcBya3sd5+O6knbSMPc=;
        b=l/6VLBFe7sZ4QebKYLx4Nhq1LKj29gKgMpMygfccVPou8r6SXaiWeotAVk1sT/CGs1
         fofRS7Rye8/c3OY+js1/abdRVqt5Y2qbbUrQbDrXc0PQL0J8A2AtzkcfpNaO2F7r/0Vr
         3gJUMLA3T36wlsiy0Rrkt4MURzlCOdQXbjzrZn6cECCEHAn4bWLAnDGPq6hsIedlIibW
         xDZ06zQAESGjMhPsCAW5WxMohp2B5cu/++MYaEHuJUHNmARkuMC5/obk0zEIFJIs9vw0
         fgb5mZJSPHLaJLDFRMR0I8lNlv98HPZB7iR4nTTqNHD37gbL+QffpQWSHh8GCPOktlcJ
         E0Ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koO2v0lPxt08MADqRPCDwIhJPu6/C66D94wC94nCsaDGGYNvIhS
	R3L5+qcEleE4romzo1auQNM=
X-Google-Smtp-Source: AMrXdXsq3KuJJPx6AlDxfmCegrMhxTa4B2WpRP/ejWuGXFrJTZ04AufVdFYBRQkUvn/53iu2H/m9qQ==
X-Received: by 2002:a2e:98d5:0:b0:280:54b:9254 with SMTP id s21-20020a2e98d5000000b00280054b9254mr1737260ljj.165.1674372058472;
        Sat, 21 Jan 2023 23:20:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a11:b0:27a:3eb5:4759 with SMTP id
 by17-20020a05651c1a1100b0027a3eb54759ls1198176ljb.0.-pod-prod-gmail; Sat, 21
 Jan 2023 23:20:56 -0800 (PST)
X-Received: by 2002:a2e:2286:0:b0:26f:db35:d203 with SMTP id i128-20020a2e2286000000b0026fdb35d203mr8001347lji.15.1674372056580;
        Sat, 21 Jan 2023 23:20:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674372056; cv=none;
        d=google.com; s=arc-20160816;
        b=d0ztGZuZdh9somwI+yW70y2Y5ZL991pxcqIL+5M0oYbIhAN85fF0xPwknqWTx6om1d
         PAy0GYg3X70Ln8FhMJ+FL9G52AC2DgqVSiRtDaiQE7y8gK3S3Z42k24dag98O67TZHev
         +c60FsfG5V2g1thjxG+zuyKCol0EKpQwREfce8rw7lsy68p9441u9ORVUwTZZuLol03o
         X9cCB3EHQSzn/JgioLbzprdi4hgOcQW/qvER1idQV+e9t5fq1wtZVGUAHNaPL6xBjuY8
         DBgHHbAlwEMeu9DpyBRr4KXF7Eau/8ivup58l2Q7efQZGwNq4CvZYM53nWE8fq+sbZLc
         ufeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=a2dbnE0ZmxswYMvj/TAyJeGi2V45WCLVe5HPt1V9CLg=;
        b=zCHaNhsRr6mL/3kJp1nUw3MdbwBVP9W6zpH3Fv5+IROsEIQK5RiF9Dqk2B3/QJIBZf
         JK9/IgxIRbF07PfYnya8JXPK4s8PFsqimtIEcqhWxW99gNcBcdULn5MKUiYSkLS40GDv
         0ee0PaRYcveaki9edxiylIK+FTTbod5EYr7LhVJGis6m7QHcpdOIvkpNBWu3oZs7pxlZ
         EFUz7uBjC3WnxRoJYf7tlsxEfH/0LBuUpla2RtFmhdXKoRDnBuLwTYNTebr1yQOfX4aG
         pTSu5joE7zj0PZsu7UwyHCWiaZnddCmvx42EjUWFXkEzXlRaTff6arV96yVPWlr7mpqn
         eqTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id i21-20020a2e8655000000b0028bce3cdc06si213263ljj.3.2023.01.21.23.20.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 21 Jan 2023 23:20:56 -0800 (PST)
Received-SPF: none (google.com: lst.de does not designate permitted sender hosts) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 4B2F468AA6; Sun, 22 Jan 2023 08:20:54 +0100 (CET)
Date: Sun, 22 Jan 2023 08:20:54 +0100
From: Christoph Hellwig <hch@lst.de>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Christoph Hellwig <hch@lst.de>, Uladzislau Rezki <urezki@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Sibi Sankar <quic_sibis@quicinc.com>,
	Bjorn Andersson <andersson@kernel.org>
Subject: Re: cleanup vfree and vunmap
Message-ID: <20230122072054.GB3654@lst.de>
References: <20230121071051.1143058-1-hch@lst.de> <20230121172057.44095a9626e7fdd05f221b1f@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230121172057.44095a9626e7fdd05f221b1f@linux-foundation.org>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
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

On Sat, Jan 21, 2023 at 05:20:57PM -0800, Andrew Morton wrote:
> > this little series untangles the vfree and vunmap code path a bit.
> > 
> > For the KASAN maintainers:  the interesting patch re KASAN is patch 8.
> > 
> > Note that it depends on 'Revert "remoteproc: qcom_q6v5_mss: map/unmap metadata
> > region before/after use"' in linux-next.
> > 
> 
> In what way does it depend?  Not textually.

It abuses VM_FLUSH_RESET_PERMS with vmap, which this series explicitly
forbids.

> I could merge the series as-is into mm-unstable, but presumably that
> tree will now blow up if someone uses qcom_q6v5_mss.c.  Which I suspect
> is unlikely, but taking a copy of a899d542b687c9b ("Revert "remoteproc:
> qcom_q6v5_mss: map/unmap metadata region before/after use"") is easy
> enough, so I'll do that.

Ok.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230122072054.GB3654%40lst.de.
