Return-Path: <kasan-dev+bncBCK2XL5R4APRBWWXTH7AKGQETMEFKWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 959B42CA7D9
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:14:18 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id a130sf985892wmf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:14:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839258; cv=pass;
        d=google.com; s=arc-20160816;
        b=tQgBfYAcBPwR4JFwSw51a2hpFQlLe9EW2MlkZR2LyYYiSQlxct6IJ2QSzZSYBW3XSS
         q9nAREAU5nv/Rn6PMoFN8iqkHShMNyaAAsjrKtm+T1PFPPSUj/qpjCGOHF+Qyif0uGAP
         lMF9Lrc+CerPlco/vbelUM2eGwnOTxov4U+USmQFkr5NrdadUn/Tw4+nmXN/FzPNiQLv
         HEkR83JmY1jei/7ZmLHzL5eH7dyppUUpYzxU8pqdbu5bef0B4X4kodSjsUoUJHrzjl+s
         U0X53JoS/v2tQ1HgjLwkW/VrEIefmOqytzvNy079rnBw6IjHAmGI6mXofvOoiqylGMks
         nTLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HJqk/WNxynj/b9zzTdWFsELRJQnCDMyMXhNo2uzSVOc=;
        b=w4e3er/DsSimCpscij5MX3RIXNsQagVWHi3V3WN35Ts2YqN/vcDSjhw8POLBQDj39x
         u0Ajaa6aBokZWy7qAb4j8DvCoegFVmi7kP9wUAC6B9yL62Wr36/T7jtev5ycovJpRN5n
         vPS59pxEjnjzBwgKfDUVWpv0AVVwoljKzUPgIq0y9QZrki5yJfOUgtLhWXNXSWX51AXW
         HmZij3isPoJ05/tPOY00MCoSE83QeOcWLewIvVwJCqrUktIBj13PmiAfJ6w3jIClREtf
         BSAlflmMs9wv3t0k8nZ5h6MaD2ZYqyv/UDlwQd49th/G7dR/iCz2a5SmCGpQ4mzfJKL4
         yupA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Wfmg+OHN;
       spf=pass (google.com: best guess record for domain of batv+0e78af3f58b0773fc108+6309+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+0e78af3f58b0773fc108+6309+infradead.org+hch@casper.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HJqk/WNxynj/b9zzTdWFsELRJQnCDMyMXhNo2uzSVOc=;
        b=P8CuABcwNjctkezPE2Oed7YiWe6XE3Vv8JzmWzbYM0HmW3U3eY0t9VgLztyd3JAB2H
         JZBLV/Kjc5Ji6aD5953zHiEVayi7axujKMEk0M69GDRWIDUwafDhYgJZMaYEV36mHMt4
         YZikjh5DYicKafjIYucf8YiuR4ITDdeStlyIGTm5WdDQxy7j+yCb2PvEsIDu1tu4asMU
         kgEVeY8sbzybodjmqEOYPk5VHoDbSy8EBo/P1WuFIz/I6f8wuzAXISIFErLm9WOvWU70
         I2SLHMRYK+zp6JosUYABp88OGUPF9XG82A8Cv/2uksM2W1Vp13Yz/xL1tC9M8hBTrZij
         IWUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HJqk/WNxynj/b9zzTdWFsELRJQnCDMyMXhNo2uzSVOc=;
        b=YNEPkdRGC9XdQjHcfIK3vKNqhz8bTRNMehrsMZcd8lHb9gyXv9mkAtFlB4xJZLwlCB
         9rY+jzJoYIHERUiD+X2W88NdEJRK0LVc6Iwno0x0CT6yA0zDtq2Ow7dPRGw8A9VHWhf0
         sWhqC0Sn74BtHCiZ53EOKhMS+POOQwuiS/NMIsa1/cLb2ZLGO676Dgq6bp1ebB4yaQ59
         +z4dXe7/bIYSZcUvkxIW1KiROGdJqI8xmbEBe+q4TUqWrXJ37OCRnqGQrHiwk99WAzoe
         LJ7mxe59ya5ZwCydrkgxkfkHtL4hnVbZxqCjg36Pn8IZvPA8pw9NHyuW42AEIifjmrZ2
         joUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+/x7L2ZwfIKQfR2p6ZmADJtml/QsRGv0bLSXrgd8lhNhpXcpP
	b9bhLSyrYwIWXCBHz82568g=
X-Google-Smtp-Source: ABdhPJxkf1bIEzQqTYhowDyu+0v5AU0sKE7CCBQuJZLRzvnXNjdHoODv6/FtLd7ijorbDSqnnHyhow==
X-Received: by 2002:a5d:6186:: with SMTP id j6mr4843683wru.359.1606839258366;
        Tue, 01 Dec 2020 08:14:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls931223wrc.2.gmail; Tue, 01 Dec
 2020 08:14:17 -0800 (PST)
X-Received: by 2002:adf:fed1:: with SMTP id q17mr4861013wrs.393.1606839257475;
        Tue, 01 Dec 2020 08:14:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839257; cv=none;
        d=google.com; s=arc-20160816;
        b=bHUXu64R5jbAkt80KLnryFZOqIylVcek6vIljwknXrD94CQaEUZzrooyQct3TvQM8t
         DwlTd6yTEq9UgxBNBrsQTuff0Q+v3iIEVsR8YfrX5Ol/BmuemJQYvXPAIsLoY5IEM9x6
         sAU99P4kIkgp3HmzN++dAFpCoyRKtm8sdFzSZnWSgHGBJp5XfEZIMUAEidoZj/lbJ8CG
         N/72tfpxlmhlmx+k4eXjcfqSaDnzQiBCK2/bTzETaCwBqNS8+bnwa0JuCX1mpikspmmM
         XfSicB+JPRVv5a3rDkyWtaLwV4zGissaYqj/PRgXwcXCLifPkFJ6Jxw6RYahOBauRujN
         JaRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RnGA5Cc3+ZrsRdSAsahPpcoJsQNEjff88u4YaGWhsTo=;
        b=UjPLb7EuM2IjvV1b5ZZr229+XRDk/u5cTXCHva4UATYRFcNS6AGecW3yHCRrH5zSgH
         Xy2kgcy9yneotq4/Y9d/c//ukPMAn0Kq9Z2Ze7vEEUxMxn12/LpoOj6lVcIs2rljKvbm
         gVyhpjbjnsLYV97fvbLPBEFtTWzJqanH5dblEbufGNlymICCxOuotEAl06ZNXae1IhYu
         9lX8aDSURw35B4FE2uExE4j+YDLvRwv8DR+EZ0qfeFT7z0rhIjw5R70m2knNSKvG19ug
         6WlN6Dhs+/sgkhw3TNAGafuGbT0r2qqyU+J8CaZsgnu1cZ+Vr8jnLreCDUnfXQFIWK5f
         zHGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Wfmg+OHN;
       spf=pass (google.com: best guess record for domain of batv+0e78af3f58b0773fc108+6309+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+0e78af3f58b0773fc108+6309+infradead.org+hch@casper.srs.infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id i3si3602wra.1.2020.12.01.08.14.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:14:17 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of batv+0e78af3f58b0773fc108+6309+infradead.org+hch@casper.srs.infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from hch by casper.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kk8IA-0003By-KE; Tue, 01 Dec 2020 16:14:14 +0000
Date: Tue, 1 Dec 2020 16:14:14 +0000
From: Christoph Hellwig <hch@infradead.org>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	masahiroy@kernel.org, ndesaulniers@google.com, joe@perches.com
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
Message-ID: <20201201161414.GA10881@infradead.org>
References: <20201201152017.3576951-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201201152017.3576951-1-elver@google.com>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by casper.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Wfmg+OHN;
       spf=pass (google.com: best guess record for domain of
 batv+0e78af3f58b0773fc108+6309+infradead.org+hch@casper.srs.infradead.org
 designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=BATV+0e78af3f58b0773fc108+6309+infradead.org+hch@casper.srs.infradead.org
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

Why not use the kernels own BUILD_BUG_ON instead of this idiom?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161414.GA10881%40infradead.org.
