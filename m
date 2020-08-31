Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 632B825809F
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:09 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id s1sf1360741uaq.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897888; cv=pass;
        d=google.com; s=arc-20160816;
        b=h6zo7u2nSnchF7JCTduUQypI7Ue6wX6WMlsJCdpAWR9mI07MZIAI+iYzeIGlWflVS7
         vNKD87XkggvqI3+saEaCt/TpOL7zHJ6SM9pGPn3Y1NCoSJomLB5ZW+x2/pqPyxZ/9+Yz
         Clk62CaSfvuriX2/nCpP8W7gLTE9UIvlPZ+TXqQ3mQojyHftXg/3uejj16TZHFoM5zex
         6W7l3TWT3wTZJAdG4QIgi4JBZW/vhtKOm6bOoHCWIyymQ32BDIj9tcH2nOCziCrLiyGv
         dR+FVvnw14P6ai1kHhQV/KCfMsCOPI+5CtLMaSGDUmmcL28QCxy7gFSO7mHswi+0z9/Y
         jOMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=ug98uxKbyJxn1DfZvqbEzpKUk70Kx0EBzIU+S52eXlY=;
        b=B/vuKd4JtKT2WNZio8UDTM5Ijx5JsFOArhCphhrbTrUd3MZvap/Hx3iGlEm2rxbE9x
         10vAtH6np/ekF8rxwOo7xSAKrm4RPyGofTAh3VQhigxQOZ4AlLnoAq34STazhrfK/Sry
         wM4xi44f9xOsSEMIsnc6368PfOflM3I2RA/5nrBhYeg1p+rXJPlWb9zsDTkkAzXmyEAu
         /jAjoDcm/HgEJRGpYV0h0sT6vLezJcREFpNve0QiBfCx8Cmn+PN8crsRNkBrCyCR/Dpf
         GDXuxbB/Harql6zcRqKHd/k6SGeyisApBvFzWkCpwcmn25ALPReg+tXhe5gmQSdumYRg
         h++g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bU7A0k8F;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ug98uxKbyJxn1DfZvqbEzpKUk70Kx0EBzIU+S52eXlY=;
        b=N3IoVWyoWHwr1zWeeE+EdJPfOKpaXniGGu8CTGHMBQdb3G423kL6ST3vyzrm9tl2PT
         y5FyyaxeMnwIdnUsNOSmRoPlfjExW03xKaz1wv+3PnwceysPWWGB9IZN7niuDF3ZFEfA
         ULWkbuOiveemH16Fz2fWtS78anfdaNU8jqRhQipIg+PfXNGJ2L7amUqz9ms0aJ+dUD8w
         LdX764QiD79zlymUlyHqZGlbMhIcqPPZpAsClJU+r+iOhHTIkkNxB0u/oe0Kg/n2qKr8
         UsohDekGTBbjlwclrWSlFCqa1KjYngLYlSpqVbgT+IM5WOUB0YSNKovhUlLRT++nnpxx
         laoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ug98uxKbyJxn1DfZvqbEzpKUk70Kx0EBzIU+S52eXlY=;
        b=mkBNe7EpxIHIkWy5SZ0gUICnGkIySDJt7jksVmCtVFN+erj5Yst81Cx4zZlyNB9i72
         H/pI10rtbcG4ZxvurUovfXZ+bPzh+fFccc36ohURoAbpfmnQav1Hb16pNmdNkjLQS4Wx
         V79nFcF8E4Rj6AFOv4zNQophWfwsTkCzJ/uf9IrxSJKmPp8yYzOxScb27aIWDy4DJGAD
         MaRnvI99xdDzSYK01IEi0uuACzyXLpmRxpmcld6f81w3KvDl01PrVXeyH+ako0zQuTH2
         uXOOAbhwjjXiZUGLmcvUWhUGF2P29CDJnc1ydScJxwZN5cSAqoFd7fAlCc1poZXTiwPX
         OVbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+BHRB2gcvg1/DGhUWEX/o7nFedR1muz9tKPcO+LquCM3QfH6R
	Mk/rf1S83AHfbi3bCKjFBX4=
X-Google-Smtp-Source: ABdhPJwkdK1OR9X2Nu0R5iFuwJkLXkyW62eEF7UotihfGx2NjL0GvhFwOEPeUX2OUGVIpLWbfuOGTA==
X-Received: by 2002:a67:13c4:: with SMTP id 187mr2352237vst.104.1598897888350;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:54c:: with SMTP id y12ls366863vko.0.gmail; Mon, 31
 Aug 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a1f:9d91:: with SMTP id g139mr2204389vke.41.1598897887916;
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897887; cv=none;
        d=google.com; s=arc-20160816;
        b=Ae8nlZ2kphddQggC1txSlZC6XaSXJHIMJnhVGKS9QEmkONRhCN3XoaWs2NPj+4290q
         kYNCokvNTAeqaXnzk8Lx/2ueQ9StzeSK4l8aqw0NwpHbrPSp3WytiTCO2TjT4fsrS6P0
         XYeaXIQpzwHuiYDmPyiYp5+K94+WdFZILpKZ2STG5ZdzzQqPEBFmHKHxTEBy08EQlc3h
         hDSppEZmgVOikajFacKZfTwpgEM4qDjVAX2v4a/jmW9xCJ0E2Hn7p9LMKNId+dm22Ovt
         kjSlnEYcFyBco6n5E8mQGJUFRHmVXK58H7xGSEemy/+SHdB+GZNKKzQFY7Mkazjrt3Lh
         mWGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=YzKQsArZyOImPEGVDzjccDM15+XaFRehj51u1kHRAtM=;
        b=wYv24OEgXy2MFXSSJyDY3aLPRV2PQyeYD0jZcFIGiGA6Q9Pth/3KYX+XULBHSmkg0H
         V0OCrAhlYBf7UPsd+uBTVRcuwwsTTkQn7A9OSdxqzQWp+8aErI+8wGJtgg9CzXtpjGaI
         n/4aNPtf/wmTUIBF1O7kkz9/59WvJj5oJn2haBLZirAmDnbQRYGEQeLvBH2hqTCYKtsa
         RotXsZW9cH6+gdmIEXt7mVmPIayvumtSGugqgYnH+x/lCRFJx2Oa1JxUGRrX8xwKhKZo
         qPpmPH+5bjpsUjXYJ6WfufSSovlRRNMPNtj4I6lSSIg1fXidJsDF0SbrMlCxullPbKuU
         4Baw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=bU7A0k8F;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y3si520669vke.2.2020.08.31.11.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F1383208DB;
	Mon, 31 Aug 2020 18:18:06 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 05/19] objtool, kcsan: Add __tsan_read_write to uaccess whitelist
Date: Mon, 31 Aug 2020 11:17:51 -0700
Message-Id: <20200831181805.1833-5-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=bU7A0k8F;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Adds the new __tsan_read_write compound instrumentation to objtool's
uaccess whitelist.

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 tools/objtool/check.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 7546a9d..5eee156 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -528,6 +528,11 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_write4",
 	"__tsan_write8",
 	"__tsan_write16",
+	"__tsan_read_write1",
+	"__tsan_read_write2",
+	"__tsan_read_write4",
+	"__tsan_read_write8",
+	"__tsan_read_write16",
 	"__tsan_atomic8_load",
 	"__tsan_atomic16_load",
 	"__tsan_atomic32_load",
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-5-paulmck%40kernel.org.
