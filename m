Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBSW57WCQMGQEVIYYDKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5387F39F7AD
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jun 2021 15:21:15 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id s16-20020a0cdc100000b02902177eec9426sf15508958qvk.4
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jun 2021 06:21:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623158474; cv=pass;
        d=google.com; s=arc-20160816;
        b=rq1lcEi8FtuJ3jI1rtTynJ9hakDYq63m5bx8+/x0LeWON0Ip/adX3Mumu8wH1yb7AA
         7W/LZHp3M5TZbAsYulNF+2m89QJfHETlQRP/+WPwtwyKND0mkHg9UbKKhulRqsmFnq1V
         C1RISSL9TC2KbmDZVkPH77KfnOpeMFkGx+B8kCoLwBsk+w1CQDBJuRLLBQE87JgOoFIw
         eKVPT/sxuXKEa9jCrk41tjCAgmxH84h4+vp/h0RYfh2iGDdfocjppGA0NSXXAK6+VSYF
         Dgbq16lXRmmI9S3NntcIfFwT+HrKfb1ylYkywJwQjen8OmVOGArUuk1XjOT4Mclcop3S
         1wLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rneT9UCyTQ40x+m8/bSUkZt/0G6qOfj0KuQ472bh4YA=;
        b=np3jGH47mUMYbOCGh6b3tzzrFZX3rUt66+neg6sG5gq+2cPBfi5D9lJ4jKWzZUeS1x
         ZFunWTKubLfK/NFYdUp1EC18mF0yrSAsdoq8ewRe4Fu0P6BFbhBJ/10vAGdeUlObRXfL
         CWmyix+UZM9LqQwSqbuN2WNEdn/hSvvtj5c5pOAovhlCRLBbr+Prwc63AM/Ryfr4BD9w
         Mnrn+B0glchPlcY1wKK5/WDMmmJ++LBFRqs0XlBuePvqXuTZkLMij/DmhIeiTHRUO2Tp
         8GTReXpYqqwOVEBuZbIdrAalmz8xnKWWhYaTfOGbdIbQs7keRQzzRRYgsfzmF8rJcOxn
         +P2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=aCxmJrDy;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rneT9UCyTQ40x+m8/bSUkZt/0G6qOfj0KuQ472bh4YA=;
        b=FbxE+t2v5nvMI2MOrBCI1Q9pXjLDMuJD46BhBcMKKI6bRojSn8ednKywCy5BfA+ara
         GfPDc7GsjppTCX7Z0EiSYBoLPZZ4R00xhhfxG4keWLFwNXzDlnJL458SFf5e0/CpiwFB
         H1tjSDwBJO/O6ZZYGByFxBNiRuoEkW9MAy9hKY1KWMgjjg4h8JRCCNGxSMFCcJaqnFSx
         nlqYJ+dmo0tZMLiefbIF0T803pGrD4YPpFeb1/qOl4UVSo+7sB8ilfWba0d9AJq4TppS
         oN86gOxwEoN4O1ZUmmOV61/ahhCK6Q89doeO7sXF+mZ2E7dN9IXoPv3bgMaSvjArGIBY
         nCwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rneT9UCyTQ40x+m8/bSUkZt/0G6qOfj0KuQ472bh4YA=;
        b=rjC9zTWpHSaOxzN9+BLmPeFjiLyszRHcct4QhPJ2D8/qudsZWBYlnr8/ogfHsrZiZp
         Q0A6TOWv04NW3P08ykCL52eVM2hO2Dt2oNxNmfv5D1oZO8SkbiPpm2pAgLU2Kqitvc6E
         +hx27YF6bmbnf4z2zxUmpsNba7e+hJYSntcTBXYCsKIdH1y7UYiNr2tfGC/DSd9dafeV
         HizWgKVm2QbAsx/eI224HdH00/T59OQRDT520x3Cz4DPeB1RfDnUVcxpehx/BYWbtQuk
         u7+OCsCnYL9reuTt8zIfTe5WQ1q5pGx/sQnsngkPZlUO+vmNbhEZEcQLj7fXJ9S0rB03
         3nqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321KUD7drXFDiexcGafuI/WjHbMJXQ7Q9HCit/lDXNCQCcgOFtY
	o7BeWv8xtuSJMzWh/mUWUb0=
X-Google-Smtp-Source: ABdhPJw/+LpiqjfrDnaymEvLlPR+0CBn4JnL01WGJ0Yn8hCp47JccnHCt96sljA5i5QPL0B2bkOCqg==
X-Received: by 2002:a37:418d:: with SMTP id o135mr21056152qka.418.1623158474289;
        Tue, 08 Jun 2021 06:21:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:16c6:: with SMTP id d6ls5731352qvz.2.gmail; Tue, 08
 Jun 2021 06:21:13 -0700 (PDT)
X-Received: by 2002:a05:6214:258b:: with SMTP id fq11mr15644787qvb.1.1623158473903;
        Tue, 08 Jun 2021 06:21:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623158473; cv=none;
        d=google.com; s=arc-20160816;
        b=TIZPrHxco5XmiAwISrirxTCp1Izm1W+x59SsIbSuPat9HBwfiiabjna83gACqeSBV0
         KiYQ1w5LBq5Ah7QQVDOIYkoUIYneUDFG4/9ofMaNYTubGmH7rTE/6eJYzmvRp3to2g5H
         VJwYD9BlhZvZHxTcW9PGZebX82qdgyAFhjjov8NNJt6kzD5W6EwRdzVkp/JtTXn0ZzGX
         4ffidzqg2qc8lagdkQ1Cj9v/EJflG4R/zdBH6etOs1OcOYLfvOk8maZMgCUrZTjE4Vl7
         JYyWs0dEtLo9uiYGvJCAQUMD46WUGVr2k9uv2i1JVZYvgu0ngoPcm5kMC/VOEvbjLtGG
         kJtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tnIxW5dO/E1OHS9H7ZMOc6x345og4zerZbSR/w3MFzw=;
        b=qAFUD2ycY77fhd1Nw4Tzbtu8MnrtIM4xOoUslTrVGrG1nweKWHYEGU8XN6meBTfXHS
         BgiNUCU0uu78aGv2jr7qzjSHpmd5fHwU/pwbBvbOBu1jEtsU/nt3S4TFNw6iCkptLNaf
         sY/mZKaPD5rWWoqZEO9tL9sp31yzPuXmGiEMHKAKgI0eN88hYo+P2Pj1VW4MorWNZ3/4
         rQMWNIlEV5M+rZ6f8VSYD8MsEVsIsfpW8B8r2yxFlpJEHGLPEP3VAU+dvKmpKCxyykYP
         Ys18KOMQvT9He0mTZdiOrXkg8cxzTC8+Z/PWO37JtoOjVj/Sr/ICegeGXJBEz312H8zW
         aGww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=aCxmJrDy;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o23si1392421qka.0.2021.06.08.06.21.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Jun 2021 06:21:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 41A0861249;
	Tue,  8 Jun 2021 13:21:12 +0000 (UTC)
Date: Tue, 8 Jun 2021 15:21:10 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: stable <stable@vger.kernel.org>, Sasha Levin <sashal@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [5.12.y] kfence: use TASK_IDLE when awaiting allocation
Message-ID: <YL9uxro0BJgLXYTZ@kroah.com>
References: <20210521083209.3740269-1-elver@google.com>
 <CANpmjNObVfB6AREacptbMTikzbFfGuuL49jZqPSOTUjAExyp+g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNObVfB6AREacptbMTikzbFfGuuL49jZqPSOTUjAExyp+g@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=aCxmJrDy;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Mon, Jun 07, 2021 at 04:23:34PM +0200, Marco Elver wrote:
> Dear stable maintainers,
> 
> The patch "kfence: use TASK_IDLE when awaiting allocation" has landed
> in mainline as 8fd0e995cc7b, however, does not apply cleanly to 5.12.y
> due to a prerequisite patch missing.
> 
> My recommendation is to cherry-pick the following 2 commits to 5.12.y
> (rather than rebase 8fd0e995cc7b on top of 5.12.y):
> 
>   37c9284f6932 kfence: maximize allocation wait timeout duration
>   8fd0e995cc7b kfence: use TASK_IDLE when awaiting allocation

Thanks, that worked!

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YL9uxro0BJgLXYTZ%40kroah.com.
