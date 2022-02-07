Return-Path: <kasan-dev+bncBDHK3V5WYIERB2GLQWIAMGQE2J4KLTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 894774AC89B
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 19:33:13 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id y10-20020adfc7ca000000b001e30ed3a496sf1547626wrg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 10:33:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644258793; cv=pass;
        d=google.com; s=arc-20160816;
        b=xOUg4pCb0GhfSQ97l/lYI2qsZlreywfLkuNsWR6o09xjquidg98lOSyNtXIQ+eE9MU
         tlf0fuMFgNEbg93e+Ig09D0u0HrzciG+1jrGBsl+MZhDE7nMDtlALnw5NgKT7l2r7PsE
         KBNM7aMxmj4w1oBXcZ+v2zxHTsGGWwZG46gC1Hop2zCQZt/cjjW7Hbe9Z+6OOzMzlG+v
         09nbaqakqzIhr6YaqUGYe9keDWbwwbOAdiKv4kVLLwLsyhc0lLbmnVF2SY514uttDR7W
         kySpCaOJTuQNCO6Qb57xNKi/BQ8qC9levfh4tX82x1ATF1TmeHdmEKtUtyOjteuYc+xO
         J/Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FTegGIcLIx2y82PxkLvqh9It2f/bQSF284U6aU+azec=;
        b=JL49VJjOkbzDaGrn+4BM5xPplz+5L9OO0eg5ne8LpXyxLq7PUCq1+4oGcHrmfFbiPd
         l560aMYSr8POuXyOKbTWkVjPpXvimkJl+naOkTZ4hL1ULXSikpjDMritT0fjv/pX8ryB
         HN3yKhHi8OAUpDPsWh2HVYBDvcJHIk8i8pOdjCw+AE8zzHPLr0wTnwYgG5gkSWZx7sN1
         tWvJBTUWph7T5xvTRDDGOz2Ia0RNOYhFFPukolB+w7AsPJm1m2x9LU9QulsRh39f+1w/
         S5lc6mcnZqFoe4IsYiCEcr+w+JUFqtYkptm0H55XnYClD3skT+lKztw5WerFMGK2MEN3
         Eb7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nuQVGnne;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FTegGIcLIx2y82PxkLvqh9It2f/bQSF284U6aU+azec=;
        b=TBsBlQWRx9EpjKikS/SlOADnBD+FZBP8FOxihCZgpQUTeFywNk6AxwlnIVDxtpLYc1
         xd9Hxjx77EZeIZMwOZuVMqtHUYbaFdD7gm+H5w3gLOh4QnjzVfcv9i2sLY14fm7EjCc6
         NbczWbxCPODCz2PU3xrhMJXHUzRfyYXxdT80qkNKbhcqmIMIt6+Dl6OpFIwugMtRzuTa
         8nl7tEerpnyta9fBMxpvDne4HrbvlBRp3FowjZLl/yUNv5fPOulO1LQpulfnpW89Q+aX
         lpftDmR45wPJOGENVPw+3kVvMHZLcUSrrPVw+t4qYhj+KIU6EQlSSV0bkfF15bivAh1E
         sAtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FTegGIcLIx2y82PxkLvqh9It2f/bQSF284U6aU+azec=;
        b=NGvo8fDMBeJ5NeKvLa0MtfyaQ+6t2kLpYM2fjSBylFZwKJFlDk1mKPo/dYT4QL1POE
         dPvz1Rjc4RyKVvFg0EYHXSSwFzyLbTURxszzzHuUml8v81JRO2FYdFLgB/JlK5Mpak0Q
         bbXYwD9vBLtPfkkY1ssMTtydUWUsXaIno3y5g1I6qMvrX97Gt5PbeaVUzOraE8WyHZ8U
         bQ7jrtgl7LwvVsTllshSFPLZjFR3Q3eA7pLuAvRbnfdD8tWXEoskWcXiwS4upn5EOocJ
         IlJHGY2atulPrTdvQ0p+DQVMFRg4LUDljimus+GjJ2MgqwWk/biCEMcQejfRU59K0qPk
         TJ1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53145SYiFmpRAQtUJrl0EOjJJ+SRiGLUzCQfSykoTgR1FlYp6qRg
	aAoL1r2Ttw07jk+mverCIf0=
X-Google-Smtp-Source: ABdhPJxvPzruvTSoXw76gq//X/ACMKzah5Sb8eEekYoS4csxP72NrhMxxffWGqmCKepHJeHIxy0x1g==
X-Received: by 2002:a5d:5283:: with SMTP id c3mr588473wrv.554.1644258793154;
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9f:: with SMTP id bg31ls72878wmb.1.canary-gmail;
 Mon, 07 Feb 2022 10:33:12 -0800 (PST)
X-Received: by 2002:a05:6000:3cf:: with SMTP id b15mr643287wrg.82.1644258792236;
        Mon, 07 Feb 2022 10:33:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644258792; cv=none;
        d=google.com; s=arc-20160816;
        b=pdNJdn7Wehu6tlGGjBHJthWk7eyoATwUMowtcr6mW/55X7YvOuGEzHN2SzJ6JhnrWP
         qu9/2PssOQeaA0P44Vka/BjNOAtIRdtagTOUF2gT1N/dPlPWLy5r6MoCK1n+WydwH9Z+
         mnpJyaIHzkuN2x2BObMkhS/dZEax4xHlCq5m61NrZMCq9714uj77VI3ozZNERlUTbtD1
         isXDaY6ykljM/rIrhhG0QOjBZFIjMazH4OYlnojAL7OWV58c8t23qZxiprycCUb0ERPL
         vhjgyYpW6u8G7P756f+GinVxdBvJQUZIGt7F9vB4Yi05i6VfJ29fuORObEYNyoI2XBHH
         jxKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UOdNmlyNPW+E8PGbp+vyT82pH5RDo7o+AEX7jRKD5jw=;
        b=Ak5ubtS+FTYAAtWXgTfDCxae7yrJ7mI6Xl+6aOjdqI9Pw4X98DdXT7IPHuGtSzqYKG
         nr5iRr8B0Wn45pe7lNPZAfB2QXCyubP7mc4kYwqGSEuFp0l5bb6my5mySyXifreCokif
         +JZAhLXXyiej+lnuZhHuJBS9PlgnprI1d9fDhJMA8PsD4BrIFbLd2hTl/W3cDvHWVmY3
         voz8ERHR71iMoNoyLsj6geqWGJQRoxCs3KAAFqNb5KpNLBi2C+1l19yoVEAeHtFXBUhB
         CJ4STa6vCRVIFkmFe8tdZgHd09cQ53oTNc1zygG5hL4/8jeU45wBHyKEIxShhVLanNnR
         O31A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nuQVGnne;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id z15si34770wml.1.2022.02.07.10.33.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 10:33:12 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id cz16so13776273edb.8
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 10:33:12 -0800 (PST)
X-Received: by 2002:a05:6402:50c8:: with SMTP id h8mr802268edb.144.1644258791896;
        Mon, 07 Feb 2022 10:33:11 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id k15sm3045173eji.64.2022.02.07.10.33.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 10:33:11 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH 2/6] thunderbolt: test: use NULL macros
Date: Mon,  7 Feb 2022 19:33:04 +0100
Message-Id: <20220207183308.1829495-2-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207183308.1829495-1-ribalda@chromium.org>
References: <20220207183308.1829495-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=nuQVGnne;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::533
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Replace the NULL checks with the more specific and idiomatic NULL macros.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 drivers/thunderbolt/test.c | 130 ++++++++++++++++++-------------------
 1 file changed, 65 insertions(+), 65 deletions(-)

diff --git a/drivers/thunderbolt/test.c b/drivers/thunderbolt/test.c
index 1f69bab236ee..b8c9dc7cc02f 100644
--- a/drivers/thunderbolt/test.c
+++ b/drivers/thunderbolt/test.c
@@ -796,9 +796,9 @@ static void tb_test_path_not_connected(struct kunit *test)
 	up = &dev2->ports[9];
 
 	path = tb_path_alloc(NULL, down, 8, up, 8, 0, "PCIe Down");
-	KUNIT_ASSERT_TRUE(test, path == NULL);
+	KUNIT_ASSERT_NULL(test, path);
 	path = tb_path_alloc(NULL, down, 8, up, 8, 1, "PCIe Down");
-	KUNIT_ASSERT_TRUE(test, path == NULL);
+	KUNIT_ASSERT_NULL(test, path);
 }
 
 struct hop_expectation {
@@ -847,7 +847,7 @@ static void tb_test_path_not_bonded_lane0(struct kunit *test)
 	up = &dev->ports[9];
 
 	path = tb_path_alloc(NULL, down, 8, up, 8, 0, "PCIe Down");
-	KUNIT_ASSERT_TRUE(test, path != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, path);
 	KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
 	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
 		const struct tb_port *in_port, *out_port;
@@ -909,7 +909,7 @@ static void tb_test_path_not_bonded_lane1(struct kunit *test)
 	out = &dev->ports[13];
 
 	path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
-	KUNIT_ASSERT_TRUE(test, path != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, path);
 	KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
 	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
 		const struct tb_port *in_port, *out_port;
@@ -989,7 +989,7 @@ static void tb_test_path_not_bonded_lane1_chain(struct kunit *test)
 	out = &dev3->ports[13];
 
 	path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
-	KUNIT_ASSERT_TRUE(test, path != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, path);
 	KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
 	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
 		const struct tb_port *in_port, *out_port;
@@ -1069,7 +1069,7 @@ static void tb_test_path_not_bonded_lane1_chain_reverse(struct kunit *test)
 	out = &host->ports[5];
 
 	path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
-	KUNIT_ASSERT_TRUE(test, path != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, path);
 	KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
 	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
 		const struct tb_port *in_port, *out_port;
@@ -1161,7 +1161,7 @@ static void tb_test_path_mixed_chain(struct kunit *test)
 	out = &dev4->ports[13];
 
 	path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
-	KUNIT_ASSERT_TRUE(test, path != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, path);
 	KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
 	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
 		const struct tb_port *in_port, *out_port;
@@ -1253,7 +1253,7 @@ static void tb_test_path_mixed_chain_reverse(struct kunit *test)
 	out = &host->ports[5];
 
 	path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
-	KUNIT_ASSERT_TRUE(test, path != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, path);
 	KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
 	for (i = 0; i < ARRAY_SIZE(test_data); i++) {
 		const struct tb_port *in_port, *out_port;
@@ -1297,7 +1297,7 @@ static void tb_test_tunnel_pcie(struct kunit *test)
 	down = &host->ports[8];
 	up = &dev1->ports[9];
 	tunnel1 = tb_tunnel_alloc_pci(NULL, up, down);
-	KUNIT_ASSERT_TRUE(test, tunnel1 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel1);
 	KUNIT_EXPECT_EQ(test, tunnel1->type, TB_TUNNEL_PCI);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel1->src_port, down);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel1->dst_port, up);
@@ -1312,7 +1312,7 @@ static void tb_test_tunnel_pcie(struct kunit *test)
 	down = &dev1->ports[10];
 	up = &dev2->ports[9];
 	tunnel2 = tb_tunnel_alloc_pci(NULL, up, down);
-	KUNIT_ASSERT_TRUE(test, tunnel2 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel2);
 	KUNIT_EXPECT_EQ(test, tunnel2->type, TB_TUNNEL_PCI);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel2->src_port, down);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel2->dst_port, up);
@@ -1349,7 +1349,7 @@ static void tb_test_tunnel_dp(struct kunit *test)
 	out = &dev->ports[13];
 
 	tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
@@ -1395,7 +1395,7 @@ static void tb_test_tunnel_dp_chain(struct kunit *test)
 	out = &dev4->ports[14];
 
 	tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
@@ -1445,7 +1445,7 @@ static void tb_test_tunnel_dp_tree(struct kunit *test)
 	out = &dev5->ports[13];
 
 	tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
@@ -1510,7 +1510,7 @@ static void tb_test_tunnel_dp_max_length(struct kunit *test)
 	out = &dev12->ports[13];
 
 	tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
@@ -1566,7 +1566,7 @@ static void tb_test_tunnel_usb3(struct kunit *test)
 	down = &host->ports[12];
 	up = &dev1->ports[16];
 	tunnel1 = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel1 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel1);
 	KUNIT_EXPECT_EQ(test, tunnel1->type, TB_TUNNEL_USB3);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel1->src_port, down);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel1->dst_port, up);
@@ -1581,7 +1581,7 @@ static void tb_test_tunnel_usb3(struct kunit *test)
 	down = &dev1->ports[17];
 	up = &dev2->ports[16];
 	tunnel2 = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel2 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel2);
 	KUNIT_EXPECT_EQ(test, tunnel2->type, TB_TUNNEL_USB3);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel2->src_port, down);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel2->dst_port, up);
@@ -1628,7 +1628,7 @@ static void tb_test_tunnel_port_on_path(struct kunit *test)
 	out = &dev5->ports[13];
 
 	dp_tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, dp_tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dp_tunnel);
 
 	KUNIT_EXPECT_TRUE(test, tb_tunnel_port_on_path(dp_tunnel, in));
 	KUNIT_EXPECT_TRUE(test, tb_tunnel_port_on_path(dp_tunnel, out));
@@ -1685,7 +1685,7 @@ static void tb_test_tunnel_dma(struct kunit *test)
 	port = &host->ports[1];
 
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
@@ -1728,7 +1728,7 @@ static void tb_test_tunnel_dma_rx(struct kunit *test)
 	port = &host->ports[1];
 
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, -1, -1, 15, 2);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
@@ -1765,7 +1765,7 @@ static void tb_test_tunnel_dma_tx(struct kunit *test)
 	port = &host->ports[1];
 
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 15, 2, -1, -1);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
@@ -1811,7 +1811,7 @@ static void tb_test_tunnel_dma_chain(struct kunit *test)
 	nhi = &host->ports[7];
 	port = &dev2->ports[3];
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
 	KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
@@ -1857,7 +1857,7 @@ static void tb_test_tunnel_dma_match(struct kunit *test)
 	port = &host->ports[1];
 
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 15, 1, 15, 1);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 
 	KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, 15, 1, 15, 1));
 	KUNIT_ASSERT_FALSE(test, tb_tunnel_match_dma(tunnel, 8, 1, 15, 1));
@@ -1873,7 +1873,7 @@ static void tb_test_tunnel_dma_match(struct kunit *test)
 	tb_tunnel_free(tunnel);
 
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 15, 1, -1, -1);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, 15, 1, -1, -1));
 	KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, 15, -1, -1, -1));
 	KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, 1, -1, -1));
@@ -1885,7 +1885,7 @@ static void tb_test_tunnel_dma_match(struct kunit *test)
 	tb_tunnel_free(tunnel);
 
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, -1, -1, 15, 11);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, -1, 15, 11));
 	KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, -1, 15, -1));
 	KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, -1, -1, 11));
@@ -1910,7 +1910,7 @@ static void tb_test_credit_alloc_legacy_not_bonded(struct kunit *test)
 	down = &host->ports[8];
 	up = &dev->ports[9];
 	tunnel = tb_tunnel_alloc_pci(NULL, up, down);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
 
 	path = tunnel->paths[0];
@@ -1943,7 +1943,7 @@ static void tb_test_credit_alloc_legacy_bonded(struct kunit *test)
 	down = &host->ports[8];
 	up = &dev->ports[9];
 	tunnel = tb_tunnel_alloc_pci(NULL, up, down);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
 
 	path = tunnel->paths[0];
@@ -1976,7 +1976,7 @@ static void tb_test_credit_alloc_pcie(struct kunit *test)
 	down = &host->ports[8];
 	up = &dev->ports[9];
 	tunnel = tb_tunnel_alloc_pci(NULL, up, down);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
 
 	path = tunnel->paths[0];
@@ -2010,7 +2010,7 @@ static void tb_test_credit_alloc_dp(struct kunit *test)
 	out = &dev->ports[14];
 
 	tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)3);
 
 	/* Video (main) path */
@@ -2053,7 +2053,7 @@ static void tb_test_credit_alloc_usb3(struct kunit *test)
 	down = &host->ports[12];
 	up = &dev->ports[16];
 	tunnel = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
 
 	path = tunnel->paths[0];
@@ -2087,7 +2087,7 @@ static void tb_test_credit_alloc_dma(struct kunit *test)
 	port = &dev->ports[3];
 
 	tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
-	KUNIT_ASSERT_TRUE(test, tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel);
 	KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
 
 	/* DMA RX */
@@ -2141,7 +2141,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
 	 * remaining 1 and then we run out of buffers.
 	 */
 	tunnel1 = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
-	KUNIT_ASSERT_TRUE(test, tunnel1 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel1);
 	KUNIT_ASSERT_EQ(test, tunnel1->npaths, (size_t)2);
 
 	path = tunnel1->paths[0];
@@ -2159,7 +2159,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, path->hops[1].initial_credits, 14U);
 
 	tunnel2 = tb_tunnel_alloc_dma(NULL, nhi, port, 9, 2, 9, 2);
-	KUNIT_ASSERT_TRUE(test, tunnel2 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel2);
 	KUNIT_ASSERT_EQ(test, tunnel2->npaths, (size_t)2);
 
 	path = tunnel2->paths[0];
@@ -2177,7 +2177,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, path->hops[1].initial_credits, 1U);
 
 	tunnel3 = tb_tunnel_alloc_dma(NULL, nhi, port, 10, 3, 10, 3);
-	KUNIT_ASSERT_TRUE(test, tunnel3 == NULL);
+	KUNIT_ASSERT_NULL(test, tunnel3);
 
 	/*
 	 * Release the first DMA tunnel. That should make 14 buffers
@@ -2186,7 +2186,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
 	tb_tunnel_free(tunnel1);
 
 	tunnel3 = tb_tunnel_alloc_dma(NULL, nhi, port, 10, 3, 10, 3);
-	KUNIT_ASSERT_TRUE(test, tunnel3 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, tunnel3);
 
 	path = tunnel3->paths[0];
 	KUNIT_ASSERT_EQ(test, path->path_length, 2);
@@ -2216,7 +2216,7 @@ static struct tb_tunnel *TB_TEST_PCIE_TUNNEL(struct kunit *test,
 	down = &host->ports[8];
 	up = &dev->ports[9];
 	pcie_tunnel = tb_tunnel_alloc_pci(NULL, up, down);
-	KUNIT_ASSERT_TRUE(test, pcie_tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, pcie_tunnel);
 	KUNIT_ASSERT_EQ(test, pcie_tunnel->npaths, (size_t)2);
 
 	path = pcie_tunnel->paths[0];
@@ -2246,7 +2246,7 @@ static struct tb_tunnel *TB_TEST_DP_TUNNEL1(struct kunit *test,
 	in = &host->ports[5];
 	out = &dev->ports[13];
 	dp_tunnel1 = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, dp_tunnel1 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dp_tunnel1);
 	KUNIT_ASSERT_EQ(test, dp_tunnel1->npaths, (size_t)3);
 
 	path = dp_tunnel1->paths[0];
@@ -2283,7 +2283,7 @@ static struct tb_tunnel *TB_TEST_DP_TUNNEL2(struct kunit *test,
 	in = &host->ports[6];
 	out = &dev->ports[14];
 	dp_tunnel2 = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
-	KUNIT_ASSERT_TRUE(test, dp_tunnel2 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dp_tunnel2);
 	KUNIT_ASSERT_EQ(test, dp_tunnel2->npaths, (size_t)3);
 
 	path = dp_tunnel2->paths[0];
@@ -2320,7 +2320,7 @@ static struct tb_tunnel *TB_TEST_USB3_TUNNEL(struct kunit *test,
 	down = &host->ports[12];
 	up = &dev->ports[16];
 	usb3_tunnel = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
-	KUNIT_ASSERT_TRUE(test, usb3_tunnel != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, usb3_tunnel);
 	KUNIT_ASSERT_EQ(test, usb3_tunnel->npaths, (size_t)2);
 
 	path = usb3_tunnel->paths[0];
@@ -2350,7 +2350,7 @@ static struct tb_tunnel *TB_TEST_DMA_TUNNEL1(struct kunit *test,
 	nhi = &host->ports[7];
 	port = &dev->ports[3];
 	dma_tunnel1 = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
-	KUNIT_ASSERT_TRUE(test, dma_tunnel1 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dma_tunnel1);
 	KUNIT_ASSERT_EQ(test, dma_tunnel1->npaths, (size_t)2);
 
 	path = dma_tunnel1->paths[0];
@@ -2380,7 +2380,7 @@ static struct tb_tunnel *TB_TEST_DMA_TUNNEL2(struct kunit *test,
 	nhi = &host->ports[7];
 	port = &dev->ports[3];
 	dma_tunnel2 = tb_tunnel_alloc_dma(NULL, nhi, port, 9, 2, 9, 2);
-	KUNIT_ASSERT_TRUE(test, dma_tunnel2 != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dma_tunnel2);
 	KUNIT_ASSERT_EQ(test, dma_tunnel2->npaths, (size_t)2);
 
 	path = dma_tunnel2->paths[0];
@@ -2496,50 +2496,50 @@ static void tb_test_property_parse(struct kunit *test)
 	struct tb_property *p;
 
 	dir = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
-	KUNIT_ASSERT_TRUE(test, dir != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dir);
 
 	p = tb_property_find(dir, "foo", TB_PROPERTY_TYPE_TEXT);
 	KUNIT_ASSERT_TRUE(test, !p);
 
 	p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_TEXT);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_STREQ(test, p->value.text, "Apple Inc.");
 
 	p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_VALUE);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa27);
 
 	p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_TEXT);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_STREQ(test, p->value.text, "Macintosh");
 
 	p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_VALUE);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa);
 
 	p = tb_property_find(dir, "missing", TB_PROPERTY_TYPE_DIRECTORY);
 	KUNIT_ASSERT_TRUE(test, !p);
 
 	p = tb_property_find(dir, "network", TB_PROPERTY_TYPE_DIRECTORY);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 
 	network_dir = p->value.dir;
 	KUNIT_EXPECT_TRUE(test, uuid_equal(network_dir->uuid, &network_dir_uuid));
 
 	p = tb_property_find(network_dir, "prtcid", TB_PROPERTY_TYPE_VALUE);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_EQ(test, p->value.immediate, 0x1);
 
 	p = tb_property_find(network_dir, "prtcvers", TB_PROPERTY_TYPE_VALUE);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_EQ(test, p->value.immediate, 0x1);
 
 	p = tb_property_find(network_dir, "prtcrevs", TB_PROPERTY_TYPE_VALUE);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_EQ(test, p->value.immediate, 0x1);
 
 	p = tb_property_find(network_dir, "prtcstns", TB_PROPERTY_TYPE_VALUE);
-	KUNIT_ASSERT_TRUE(test, p != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, p);
 	KUNIT_EXPECT_EQ(test, p->value.immediate, 0x0);
 
 	p = tb_property_find(network_dir, "deviceid", TB_PROPERTY_TYPE_VALUE);
@@ -2558,7 +2558,7 @@ static void tb_test_property_format(struct kunit *test)
 	int ret, i;
 
 	dir = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
-	KUNIT_ASSERT_TRUE(test, dir != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dir);
 
 	ret = tb_property_format_dir(dir, NULL, 0);
 	KUNIT_ASSERT_EQ(test, ret, ARRAY_SIZE(root_directory));
@@ -2566,7 +2566,7 @@ static void tb_test_property_format(struct kunit *test)
 	block_len = ret;
 
 	block = kunit_kzalloc(test, block_len * sizeof(u32), GFP_KERNEL);
-	KUNIT_ASSERT_TRUE(test, block != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, block);
 
 	ret = tb_property_format_dir(dir, block, block_len);
 	KUNIT_EXPECT_EQ(test, ret, 0);
@@ -2584,10 +2584,10 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
 	int n1, n2, i;
 
 	if (d1->uuid) {
-		KUNIT_ASSERT_TRUE(test, d2->uuid != NULL);
+		KUNIT_ASSERT_NOT_NULL(test, d2->uuid);
 		KUNIT_ASSERT_TRUE(test, uuid_equal(d1->uuid, d2->uuid));
 	} else {
-		KUNIT_ASSERT_TRUE(test, d2->uuid == NULL);
+		KUNIT_ASSERT_NOT_NULL(test, d2->uuid);
 	}
 
 	n1 = 0;
@@ -2606,9 +2606,9 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
 	p2 = NULL;
 	for (i = 0; i < n1; i++) {
 		p1 = tb_property_get_next(d1, p1);
-		KUNIT_ASSERT_TRUE(test, p1 != NULL);
+		KUNIT_ASSERT_NOT_NULL(test, p1);
 		p2 = tb_property_get_next(d2, p2);
-		KUNIT_ASSERT_TRUE(test, p2 != NULL);
+		KUNIT_ASSERT_NOT_NULL(test, p2);
 
 		KUNIT_ASSERT_STREQ(test, &p1->key[0], &p2->key[0]);
 		KUNIT_ASSERT_EQ(test, p1->type, p2->type);
@@ -2616,14 +2616,14 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
 
 		switch (p1->type) {
 		case TB_PROPERTY_TYPE_DIRECTORY:
-			KUNIT_ASSERT_TRUE(test, p1->value.dir != NULL);
-			KUNIT_ASSERT_TRUE(test, p2->value.dir != NULL);
+			KUNIT_ASSERT_NOT_NULL(test, p1->value.dir);
+			KUNIT_ASSERT_NOT_NULL(test, p2->value.dir);
 			compare_dirs(test, p1->value.dir, p2->value.dir);
 			break;
 
 		case TB_PROPERTY_TYPE_DATA:
-			KUNIT_ASSERT_TRUE(test, p1->value.data != NULL);
-			KUNIT_ASSERT_TRUE(test, p2->value.data != NULL);
+			KUNIT_ASSERT_NOT_NULL(test, p1->value.data);
+			KUNIT_ASSERT_NOT_NULL(test, p2->value.data);
 			KUNIT_ASSERT_TRUE(test,
 				!memcmp(p1->value.data, p2->value.data,
 					p1->length * 4)
@@ -2631,8 +2631,8 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
 			break;
 
 		case TB_PROPERTY_TYPE_TEXT:
-			KUNIT_ASSERT_TRUE(test, p1->value.text != NULL);
-			KUNIT_ASSERT_TRUE(test, p2->value.text != NULL);
+			KUNIT_ASSERT_NOT_NULL(test, p1->value.text);
+			KUNIT_ASSERT_NOT_NULL(test, p2->value.text);
 			KUNIT_ASSERT_STREQ(test, p1->value.text, p2->value.text);
 			break;
 
@@ -2654,10 +2654,10 @@ static void tb_test_property_copy(struct kunit *test)
 	int ret, i;
 
 	src = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
-	KUNIT_ASSERT_TRUE(test, src != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, src);
 
 	dst = tb_property_copy_dir(src);
-	KUNIT_ASSERT_TRUE(test, dst != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, dst);
 
 	/* Compare the structures */
 	compare_dirs(test, src, dst);
@@ -2667,7 +2667,7 @@ static void tb_test_property_copy(struct kunit *test)
 	KUNIT_ASSERT_EQ(test, ret, ARRAY_SIZE(root_directory));
 
 	block = kunit_kzalloc(test, sizeof(root_directory), GFP_KERNEL);
-	KUNIT_ASSERT_TRUE(test, block != NULL);
+	KUNIT_ASSERT_NOT_NULL(test, block);
 
 	ret = tb_property_format_dir(dst, block, ARRAY_SIZE(root_directory));
 	KUNIT_EXPECT_TRUE(test, !ret);
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207183308.1829495-2-ribalda%40chromium.org.
