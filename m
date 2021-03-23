Return-Path: <kasan-dev+bncBCAPVX4AQUOBBG4T42BAMGQEMZL3YCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 462993457BD
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 07:24:29 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id y16sf561674oou.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 23:24:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616480668; cv=pass;
        d=google.com; s=arc-20160816;
        b=aA1XHN4AVtPvUZSuuDd1DZ/p/4JoTH96IihFhvyRh+wtIO28t77kvzgjNlTqzbcX/x
         NbHYol95ew6aukNH60GQOFHZBXvUGyoEQ1eWALlTqHaV0J6gBXZxE+1wJHo938irAz0z
         HISJDoTN70DNoQ1GOeV0Dvl7QjilghA/ibXtSZ6pQKZMP/n0/zlll42LMgjFj3fygZvf
         cL3lFYr+fSZGF8fDuIV1URsnXNaGWyO5F0qxyzi/1ZFATweOnKxVums57WU1MCyyVmVI
         +SrCnjR4jDSkj9IHBz1uayCMsAu1NMS01JYIgvixoAwioDp4D6fgeiBt4uC/9+cisUVe
         t1sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=1DRBygzsMZ5+vQhuFd6owSgL5rH+gA60UVMJSfDZDyc=;
        b=lA4RHuTXU8KETXhmiNfBjd9UGvYW594ZPQaRLtBYNPgWMcKieRUvCRgxXmugftM5z2
         1jsJktO1V1T5QsD7G30vU7qSy//MLZ0h88ipOmRVvjd6AA+L5JkJ0DgdnWZmGLSTc2BX
         eoJGWng3F0j9ReBHbRDDJ+9PluiXw0h/DZiJPkp/nsG1MRZNrmV4hB3zOIruPRUMYMv1
         ujRSBIUrmik3MQacOWVSJapA/C6MVhxTRRHtNvN688t0lBmCQM1LfL7B6IMde6J/zebz
         oCDKC2RRxezuDTJ14jiNo82YQ7ksbrVbLJQVknLgQvm6VvjLRX7Lq/kEnJv6y/OePgUl
         s9CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MC8sooYL;
       spf=pass (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=tl445047925@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DRBygzsMZ5+vQhuFd6owSgL5rH+gA60UVMJSfDZDyc=;
        b=lQ11ka2j2O5cUe3e3AtTS3qo+/BuBPxFncZcakf+47IP1jqBdTGnL/DSunZ7oXHjdN
         xWH//GDxi4mcCY1t3pyM1oKm12T1bqlcprooisY9OvLt/LlCFp4kfqwsANaSfwu6H5g+
         iEkAw5Ycxggl0nUwVVcDcyTtr6rzifv3TEUODr+35Bd+aXHfmXsl25fyzoJ8KIaCRaFo
         RF2csmD3uh3XcBW8WZwDxjDmFwhKwWm753r25+szTSODfimbe0qwJ5wlwdmgdbsgWU1g
         d70fTSnGOyIGbKghQr8DXprv8wxJvaQ9gSI39H6ou0f/0/G8MkKNy/+Z07thv3N+meVE
         JZ3A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1DRBygzsMZ5+vQhuFd6owSgL5rH+gA60UVMJSfDZDyc=;
        b=EkkOSf85TUnAqeq4zUZlo9eUKvY3YYwslHSwUtxgqkMGGbY7hYmMVQd+kR93V2TOLI
         tRKc6ca2PqWVIiaL9EuujxlSesI4FBQQvzy+qYG1eczxMZd1GM+APDwzN5wjHXCNQER+
         eXMfUGZcvgGr3wcmmM4BIB3hTtvIMp2ZFGF8J8ixvNBiElaMGWiwewIlm5mK0/5x2VKo
         3IPGonzYsTHpGLGyfejmRZMfkAVJZsp92PRJHJyq52ZX140nraO95T5gwpwHdDhbUxAR
         ejhWsSmC6ZdCItoTjIA6g1E/H4a8fTTKGGOFaKHggEu7nP//BvIrjTnlybndnzDcq2uy
         /CZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1DRBygzsMZ5+vQhuFd6owSgL5rH+gA60UVMJSfDZDyc=;
        b=PzvoWVQpHULzvmJVvdm9xG16wuI+rFmq36QNPwe6/hk/p6qXRoPareMMZZH0TZWx/V
         Bh3SyRgGsbLlbX7X2sZqwbl1BclouRlGslPOifdGLEzEGdnvr/Fpav8QhEa+bH/DL7s6
         rUEy3xNuGhScRFTv0GZoSlqnFrDi720XdVsjjnnjq5xgukoBZIB/nRqvog5bcJRr/ys6
         d8vBsuT3BGywm3Job+NvG3rPuOoR9bVhKxOozr/wtpIhj8JQEoz6LY43/SJ66ojyb9g9
         Mhc9l51nWmw7GUcNuhYiK8ZjG1gdBS4ftKDf2fe1p42KNXU4/xCqr2pvgfMQGSJwV4+G
         b0ZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QhpbLJBDVB80k6ckqKnW/nsabjawU2rzFLn1sAjEpngn/EFmk
	r/Bbf/vn/TTqTX4Vw/SSk40=
X-Google-Smtp-Source: ABdhPJy2ypJuixKgRA9t33EGMs2JkuJbfNsQ991bAn6DcyUKpRsS74TwM301EJrTym1NBRAN8hLvbA==
X-Received: by 2002:aca:df54:: with SMTP id w81mr2257843oig.108.1616480668006;
        Mon, 22 Mar 2021 23:24:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5551:: with SMTP id h17ls3596667oti.1.gmail; Mon, 22 Mar
 2021 23:24:26 -0700 (PDT)
X-Received: by 2002:a9d:68c1:: with SMTP id i1mr3118606oto.169.1616480666860;
        Mon, 22 Mar 2021 23:24:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616480666; cv=none;
        d=google.com; s=arc-20160816;
        b=fewY7huldpqBYCMcZ0jguJWdR5jH8x+TmiUcdQDLMRtjQ1pKqK9N0DxfSaKo0y4erE
         Ai6c8hrTmlGrYTyoaf8bFbY+UENHWsrQxoti0KJflgE6BCMx0CHIpdZLLNDU9dc9SNLt
         /FtsKbYbYbW1FYvD4M47V1WmsGaf50DZUClLB7k4K0mmNJslES8cEkmlnpYlwqAQL6Hg
         MrAXwvcVbozdLMJyWvdRxyG9hPAmnpW5Cs0TM/S67begIkZKgaiYgpnRzm/pclsxaFCO
         aTHWnX5exjMBAv//IvwoCGIv4PYERXu/ZskkiVLOeBM/76ZK7kLMvd/EVDvJ4rF1E8+4
         zG/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=fD7whzkga1n41mwitAEf7/1mswAaRzgKbqj4Zkf0V/A=;
        b=uKfuLA4HNVFA8yxfd+4cQz4BdTAhHbfBI/fqpPktvsK4sdns54mKv0SH6cXv5kgdju
         6rKLm9GXA/R3461K3qYcrM0pyDVH2qcVcAX3LkzS2kPGsS0bGyML8WQU6kvTv4aSPmuU
         N4Z/eH61/TfPtoEkWkd8Rvq9cm4ehSzNxq6BRBlsDMpJWqBpOZyvUtFgmwxzBuvjRgZG
         6BVwWFwe1aGAg4o65NUmn+dmW3kJI3aYJvZlvY8eVZ/apgMTL/AAv3kbJKsox7aFWPak
         AV6/QwGWwSagRS4HOwej/26XEjkqBtPPKzFChHAjrpl2+iWQNomULaXsChTkLsUzW+sB
         5gGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=MC8sooYL;
       spf=pass (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=tl445047925@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id f2si1371589oob.2.2021.03.22.23.24.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 23:24:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id r17so10675378pgi.0
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 23:24:26 -0700 (PDT)
X-Received: by 2002:a17:903:304e:b029:e5:d43:9415 with SMTP id u14-20020a170903304eb02900e50d439415mr3765538pla.42.1616480666254;
        Mon, 22 Mar 2021 23:24:26 -0700 (PDT)
Received: from localhost.localdomain (ctf2.cs.nctu.edu.tw. [140.113.209.24])
        by smtp.gmail.com with ESMTPSA id t17sm14999564pgk.25.2021.03.22.23.24.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 23:24:25 -0700 (PDT)
From: tl455047 <tl445047925@gmail.com>
To: dvyukov@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	tl455047 <tl445047925@gmail.com>
Subject: [PATCH] kernel: kcov: fix a typo in comment
Date: Tue, 23 Mar 2021 14:23:03 +0800
Message-Id: <20210323062303.19541-1-tl445047925@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: tl445047925@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=MC8sooYL;       spf=pass
 (google.com: domain of tl445047925@gmail.com designates 2607:f8b0:4864:20::534
 as permitted sender) smtp.mailfrom=tl445047925@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

Fixed a typo in comment.

Signed-off-by: tl455047 <tl445047925@gmail.com>
---
 kernel/kcov.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 80bfe71bbe13..6f59842f2caf 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -527,7 +527,7 @@ static int kcov_get_mode(unsigned long arg)
 
 /*
  * Fault in a lazily-faulted vmalloc area before it can be used by
- * __santizer_cov_trace_pc(), to avoid recursion issues if any code on the
+ * __sanitizer_cov_trace_pc(), to avoid recursion issues if any code on the
  * vmalloc fault handling path is instrumented.
  */
 static void kcov_fault_in_area(struct kcov *kcov)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210323062303.19541-1-tl445047925%40gmail.com.
