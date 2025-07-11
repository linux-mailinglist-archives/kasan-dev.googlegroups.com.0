Return-Path: <kasan-dev+bncBAABBAG7YHBQMGQEZ7F7ZHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id CE408B01108
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:57:22 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-31218e2d5b0sf2894952a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:57:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199041; cv=pass;
        d=google.com; s=arc-20240605;
        b=EKAEN4kf/FKQm+BQGe2IzUWdZI1t+Zq6IIX5ZVNsTAHVClD129p14KkEfBapXZycc7
         r+K3JprSisdAFhWEyuabb8eBZrExbKKWXVImcjV0BPNMkv/EtO7PjV8cmu8T2fepZ4Yi
         uqAfDP2eLNARVxyKu4u+pin4263bunKwelc0o5nE2q5D+zpaX3IfFwjgiMRnTyuunXI2
         Bkq3hLwVLOxj4s7mssIBxLz/KLxyPgNN8CQaZT3O6eiglekd5ufBTkNlg5Oj6TYqz7v0
         iKsaopPnMsrQxQxjpv4w8zYKSGq+pxNqXTn37+jfR5MFh8W3qfG3fahCMtcoTACxhO+y
         qJ1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9RMWw/NA1tyAPBc1wwM6zcMgGUyvWx4pwSLD180T+rg=;
        fh=EfAHsETTOMXsw2TGHgQTCKXtLDTDsZXRSBNknnTHwlA=;
        b=bZBx6Bf2DaNe8U+QtkQktPX+OLbgn7Vx7GXgYe3Z8IVZ2Qg4vmcWqstPc+MsD3JZXO
         sLc7/0DkviJlGsn/L0kGhR1vOeMnVJn58u5RJZp8XEY1bog6rwax2nuoHJqlTrTLfyhV
         aHrcoGvhabOsip1bGml8FbLosjiFf8B0RlZFPlBR/DcBVkoPqDtVMargHtFj4ekcQwzL
         5qgHJnfHkTorQSneNcQOn9sJ3QiAKFf/rN/7/d0CsJ6rsLo3Dmm0sbnm0P4RX6YZioXc
         GVtrs+wVVU+Y1DfOl3mfZVxtPUkhWMbEqDgziXsIm6e9ABJyiJpnxALGIykOAtEDPQGp
         0aWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NLhTvbdN;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199041; x=1752803841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9RMWw/NA1tyAPBc1wwM6zcMgGUyvWx4pwSLD180T+rg=;
        b=pdKFoIkZGNSmBMWne4gLqgD/EIu33I5euoWsMYhwisyAkLs4C3xcBpFs87i+58meDA
         44ZtpY3M/IkZt5l0YHy8T32a5pr0L37usXt2r12co+ITmEZmaq7cdQn6IlSE1bre7R3p
         cDgs4vns62yd8kzxTx/ljy2JNUkfjYKGVf3AjHXnHW09tkZu957GJPhFl8rnetXlHafI
         Mm/n6rbXBiwt5C3y3Yj+iWWWYocXVjUJ3k8NruKaH1iIancHkvibCbvZonoVwUyMHOGl
         k/yUdGt81Yu7farmyz4I3tCxrIM8yCE43lO+BPv8Gt5bB+Nl7mnX12a+VGK7a+9AqPte
         m1gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199041; x=1752803841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9RMWw/NA1tyAPBc1wwM6zcMgGUyvWx4pwSLD180T+rg=;
        b=UvIfsTQ43GdTN4GPewT6WlCWTSdX/1BA7A3tp24cu50jMCHMKnUpMRg9Jz6EflJ3ws
         UdQX3owynHA6lf68bOIADdp+Hg9gPmTsNxZwPKs3TkIiZmBDqnm0pcw26dis80Jk+25f
         Ev/f2S2+9qmnzaKL7WOAEtEBtbT0yZ6H7go3wXcF3RN9lcTxABkLHomFhDDTDp2dh+Bn
         aZkGmgLlws7UIwuSF+oIjG0pWl9wEzVdz2pjQ6hSx8sFDvxc4einbzm8REYNGM9NB5sW
         35jC56iBY85LWNCrk4bhqPadcp0DTIWmNyJYBGTaxCEEZjgOWUk55/f+x4Fg/SL9n7vL
         GAew==
X-Forwarded-Encrypted: i=2; AJvYcCVKP7uS9ZvlfE+NG3or+Du9Q8qR/qHPiDnk08hBrBPLTpjfFAJDTKiOveD8CC4N+HmPME4d0Q==@lfdr.de
X-Gm-Message-State: AOJu0YwBlkvhwLKkrWj2V+V0h44Lkmv3GWEBWr0jX3XGe6L/J3/r7+U8
	2np3iLOLv2pSG0Kr3Ofjz2jJMu7FZt6KOMqnERhjR3icoYgL+6D/phc8
X-Google-Smtp-Source: AGHT+IEeyzAth72kla4Y0c6xjaipE5C8RaK3trd/tw7IbKFbOUMtADefLR2qdrAC7DXJtlE+1pSX3w==
X-Received: by 2002:a17:90b:4a81:b0:31a:9004:899d with SMTP id 98e67ed59e1d1-31c4ccd89b4mr2559701a91.18.1752199041174;
        Thu, 10 Jul 2025 18:57:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfo3GuJ9T57fghbFNX+ODZ8dCHo1MEDsYZrAykK4vHXRg==
Received: by 2002:a17:90a:d41:b0:315:40ea:75bd with SMTP id
 98e67ed59e1d1-31c3c8cc3e4ls1206484a91.2.-pod-prod-06-us; Thu, 10 Jul 2025
 18:57:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0JOW+l0AVTE4eQ9m8ZVBRmJFWddknTN/LRe8+FweS3VL4lkUQwk4sBd8dETQju2rVgTmyrook2e0=@googlegroups.com
X-Received: by 2002:a17:90b:1c07:b0:311:9e59:7aba with SMTP id 98e67ed59e1d1-31c4ca64db7mr2342514a91.2.1752199039680;
        Thu, 10 Jul 2025 18:57:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199039; cv=none;
        d=google.com; s=arc-20240605;
        b=FleWXeUhTMCbOK/mjE0fOanBlUD85VSHM65XOb7xn2WHgoqABJF0Dg8M5+sJeaezax
         XqcRHF7+ElsOA/+AMhb2zQLjkmClCPsADf1TFD9H74gt9jytzeeVKbl4GsL2j7/o6AiL
         PM/kR+L1wD8f+OqZfYlRUIBpOWtyuRbYyxyuj2ZXj8Cn2UxQqRQHLISQFOhiuUXGQMt/
         PL/XCMNqXvQ6PA5gHg/QkiUpMpY0GQfvB9taQ8kQOQKaxoiDPqJDYkbp5lMxApQZ2dOy
         EWDKQXGkMKb6TT/qpSqdhv5cFAxRdsso73VvsFwAN/RcMmOU6Km/llfNk6bMU7BUkIse
         9eog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZTzMdAzS0MUZsG3INWu7KjxgVxyuWBJkeq2Ek55G1bY=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=JeijcJFUVTEBwN0Xg/1FOhcU8XM8VeLDko4+X6w9g1SjbBH0zFnaLZgcgzDgtWPdfv
         hjC0Am4Ezf26chfdhiptl4z7mRhG0KefPusvjD7MQDMnehiY0hVP1tcHTsVjfzLpfhaD
         q2jl/Xr+Oo8MsSJd1iSKc0lR+0o0+JStvglZenKocFcXfBEkTr/eshTDKa2zRmJ6fJYu
         Go9sXfaSeEDn6HYlbZhcjKutFvJHbh6nMjWvQ3iMrbe52DEOGbKAHgw/RzwEsqLGcOAq
         wIEP64Eou2uNuruGwZ7pbzHUJJBai6fYGm92UBjNQF/F5ASm65JT5Zok1FsccgYyO0mn
         BiUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NLhTvbdN;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c3eb4e0aasi122885a91.3.2025.07.10.18.57.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:57:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 00D515C6F4D;
	Fri, 11 Jul 2025 01:57:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0D0C2C4CEE3;
	Fri, 11 Jul 2025 01:57:13 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:57:12 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: [RFC v6 6/8] array_size.h: Add ENDOF()
Message-ID: <37b1088dbd01a21d2f9d460aa510726119b3bcb0.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752193588.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752193588.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NLhTvbdN;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

This macro is useful to calculate the second argument to sprintf_end(),
avoiding off-by-one bugs.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/array_size.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/include/linux/array_size.h b/include/linux/array_size.h
index 06d7d83196ca..781bdb70d939 100644
--- a/include/linux/array_size.h
+++ b/include/linux/array_size.h
@@ -10,4 +10,10 @@
  */
 #define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
 
+/**
+ * ENDOF - get a pointer to one past the last element in array @a
+ * @a: array
+ */
+#define ENDOF(a)  (a + ARRAY_SIZE(a))
+
 #endif  /* _LINUX_ARRAY_SIZE_H */
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/37b1088dbd01a21d2f9d460aa510726119b3bcb0.1752193588.git.alx%40kernel.org.
