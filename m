Return-Path: <kasan-dev+bncBCTKRTXYNEIIXS47TIDBUBG2JYS52@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 673BB5FD7AE
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 12:16:44 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id b34-20020a0565120ba200b004a2542bd072sf358994lfv.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 03:16:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665656204; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cjd/xrGyN+3s/ZpK4buGmR8RLkuKqPpLA8I1st+PzDXcqIj/5LIlZioVPvFoKjEVl+
         4xFfkUB6CV+0OgcgdcvpN/FAXGL/hE4aAdHTKThccDXzQjP69vSXhet9MhhhuvTTbR/T
         JqnzZmJKcmAg+HmkqExbzQaDGeLdp2xN8ea1m0Jvq1KDVcASAjOf6xKoNdmK2EeH9yBi
         tw94cO2LBRhwZItrab8+jzfic9cNcnBxYsC8GR7sJXjEUvD11Zrrsz3tXuYXcROiKr8k
         PstHMOMAS0594LCvPRn/xL9dWXh7WYmAcYXbkjX50t7FfcSnuWe2CkIgUqfH9KWFrKTV
         RglA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6PEDzz4R+t5mJiEjn8RYzinawVcg3d/li2+jcUtfZ7A=;
        b=y1rnhPUFCjRi5e2FYWAJbZxPW1D5bolY/UaOlHDU69sG0NgqYeqi0pwU2th9XbonJP
         geBMtfp55fhvp1ZvK+UyASnUFwoouyfvjHTEv1A+jHZg9lS6TltNDpPTP9XW41zpIOzH
         B0DGzdnAN2zNXz36USX0SOzBchH3ia+piYfuH4eAl0EHildTD54SvMr64Eo/OxXFOhEs
         LCsWqJUbzXlckBqgnOVUsJjhXTHfMt5lswBawobnfX9VfAoF6S4ZLar2fH/zD94sKEGu
         P/FK8JT6YDWmaI7PIyDJWzFdIOR9DidhlBhkrk6fjDhommlZZJh5cLc841bJf2SmGg32
         8zSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of fw@strlen.de designates 2a0a:51c0:0:12e:520::1 as permitted sender) smtp.mailfrom=fw@strlen.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6PEDzz4R+t5mJiEjn8RYzinawVcg3d/li2+jcUtfZ7A=;
        b=NsrjIp0Avioo8cjQg7LVjR3RCXpJ3o7eXb/QynJLKhLIw55Jcj8y5RGVZwiW0EPy9S
         PEelwJRzM65ceWFOjlXlYtz+NatJZbZzr08ZaP2vGepJiBDaE50nYAMOAt7JpCmV7y5P
         zzfej0uL2nbkGF4BPJn8NnxE908VEQ+NStBe6Sosz9U9Aw4jkgDFm82cJqleYbsYL9+9
         JRhExr4c6R71ipOvajLeSS+bPsua2oTKaH0eXMXlviP6bAI1IKLaX7WMiwe5G4ZefhQb
         T3ximeNZqr0y7Wx3ox+vjHdp1u6gK6O3ROZGqw+uupcbB5ekFZEbjdhv7DX3esOkrLeV
         +Y4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6PEDzz4R+t5mJiEjn8RYzinawVcg3d/li2+jcUtfZ7A=;
        b=q4XZItUvvjP1VhgFGC1h/vQYEY/592GGOlTJic2dWbaKb5cD1FCfc7mmquTnefglwO
         sEqXqogWHMPD83782tcYqssfKcyVbMeu5Audr0Qptll29ExmI73MWcIli559wXLSJhuH
         ctAo9X+FswVhV7lL+0smNlHWWW4Vvnx7LbOPXs8L5w8lgESqAT9SOFNZqtiAB0/CyIq/
         f/so71Op86UVJbvwBWA10bV4I+lVtAbzJQC4TJOgbxid8UrkfLAdv6iLII+gpnnNT165
         JW6ZdXoH0fWpIEhQFYnu41O7X1GMax27hY1QMztqIqIpdrKFO0Wjt+8DP6v+N5zzzPN/
         0+dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf27CPtIR8KcAhefP7N9fTUF1MHSn76ZihyRX5F6b7Yp/XV6it+s
	SSEGQycDhQo6njtUhLwLrsI=
X-Google-Smtp-Source: AMsMyM7xzxNWGNIjMPuzWU+HkddqMdoXH8OKk/DLVMF/j8MpAO/AWkhUDC+8bPYWAUwJD0eHH3LcwA==
X-Received: by 2002:a05:6512:1193:b0:4a2:70b6:3191 with SMTP id g19-20020a056512119300b004a270b63191mr11539253lfr.563.1665656203802;
        Thu, 13 Oct 2022 03:16:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2103:b0:4a2:3951:eac8 with SMTP id
 q3-20020a056512210300b004a23951eac8ls682158lfr.0.-pod-prod-gmail; Thu, 13 Oct
 2022 03:16:42 -0700 (PDT)
X-Received: by 2002:a19:7003:0:b0:4a2:40b9:dea8 with SMTP id h3-20020a197003000000b004a240b9dea8mr11283329lfc.688.1665656202519;
        Thu, 13 Oct 2022 03:16:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665656202; cv=none;
        d=google.com; s=arc-20160816;
        b=KI2RmQVWVSTDk03Qvmogcd8/O4e1YQo/EOsde8Lb8UB/TdtnacEViuUxVmlNTXn3a1
         axLi46m0mHG+AnzwpEiFeYotVbg4/hBGPr2xuBTxd+qeOHWAQkBf3blEw9fkDd2cB/tH
         z+zULKGFJX19z6Xc+S1tzSefDO6upxK1b6XU7M16ZsC5/did1+HuSCd4cpw7KBUToYvO
         FlP6M3XZuR/FmPWfteJpZ5MMi2LPJDPqaH0QoSwuhpmMGWV9DH+3xLu2GFXC/boVqCyD
         8KWS1ju98crTm662hNDv1NS9j1X0DQ/1mPJShERuhxYfYcgvdUeoj91UtMZPSYHOYrlI
         oDlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=cf/mi8PiR7AOB7uAV/J+8RsCEujUPjdzXkLzGlxBC8Q=;
        b=eF8SLpX7ee1dKxqNs4eM2sU6XlPbsYsDcuuS99BgC5kbOYhXe0nVrf+mkSYQEOLN8s
         yAGbF8tg/MJ6WmHCulKCHe9jS/k+KhxH4T0NEwgBnWA3t2kmxiOkzQtm/jGUTaABWCPb
         E20XxqkoF0UsIZQ0vv/uIED3+FcctZ3W/zmmxQps/LXrw67eNDcroJ43yw7jvL/EOUn3
         xYuYmzWO/ptTH2s6vO2SIppWwZ85u8CyfTbU8jmCGAQSlfwxD4jvlr/SAoCvxP7pLt3R
         lLB5ocS46J7/bddd16mETfi0sg6PHU/acKHP2RA3McSLnHhck0mraZX2F6E7749g3YFx
         HlMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of fw@strlen.de designates 2a0a:51c0:0:12e:520::1 as permitted sender) smtp.mailfrom=fw@strlen.de
Received: from Chamillionaire.breakpoint.cc (Chamillionaire.breakpoint.cc. [2a0a:51c0:0:12e:520::1])
        by gmr-mx.google.com with ESMTPS id p16-20020a2ea4d0000000b0026e8c45cf59si401557ljm.8.2022.10.13.03.16.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Oct 2022 03:16:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of fw@strlen.de designates 2a0a:51c0:0:12e:520::1 as permitted sender) client-ip=2a0a:51c0:0:12e:520::1;
Received: from fw by Chamillionaire.breakpoint.cc with local (Exim 4.92)
	(envelope-from <fw@strlen.de>)
	id 1oivGV-00028B-QF; Thu, 13 Oct 2022 12:16:35 +0200
Date: Thu, 13 Oct 2022 12:16:35 +0200
From: Florian Westphal <fw@strlen.de>
To: Rolf Eike Beer <eike-kernel@sf-tec.de>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Florian Westphal <fw@strlen.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Thomas Graf <tgraf@suug.ch>, kasan-dev@googlegroups.com,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev, netdev@vger.kernel.org,
	sparclinux@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v6 5/7] treewide: use get_random_u32() when possible
Message-ID: <20221013101635.GB11818@breakpoint.cc>
References: <20221010230613.1076905-1-Jason@zx2c4.com>
 <20221010230613.1076905-6-Jason@zx2c4.com>
 <3026360.ZldQQBzMgz@eto.sf-tec.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3026360.ZldQQBzMgz@eto.sf-tec.de>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: fw@strlen.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of fw@strlen.de designates 2a0a:51c0:0:12e:520::1 as
 permitted sender) smtp.mailfrom=fw@strlen.de
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

Rolf Eike Beer <eike-kernel@sf-tec.de> wrote:
> Florian, can you comment and maybe fix it?

Can't comment, do not remember -- this was 5 years ago.

> Or you wanted to move the variable before the loop and keep the random state
> between the loops and only reseed when all '1' bits have been consumed.

Probably.  No clue, best to NOT change it to not block Jasons series and
then just simplify this and remove all the useless shifts.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221013101635.GB11818%40breakpoint.cc.
