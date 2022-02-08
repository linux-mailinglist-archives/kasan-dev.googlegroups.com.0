Return-Path: <kasan-dev+bncBDHK3V5WYIERBVVYRGIAMGQETEVKFKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 4957D4AD81A
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:04:39 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id k18-20020a05651c10b200b002430548189asf5965880ljn.15
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:04:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644321879; cv=pass;
        d=google.com; s=arc-20160816;
        b=kmPRb/bApLHH6DKiXbsAe0/BvjFjgr831Os/kXTfHkKmDZ++wuAXh0ngQjCyjMWO9D
         Dz0nx+1By3jeB9Ep65C14gVVo3aO3oHyKxOI6B0KnJz5t5mRka6+96satHl4rlhpEM9g
         Hkw/I8rkL9eXYfPZIVwvwiphONUHpqZw7K5Iku9pLazxGMQfSQIEWFDRIW6+fiM3lQbW
         bmawoAr4pJ20Z4i1KqO8OPf7iP03HU/Sjj20gkmm8IDcZKwWmNlKp5QxSjvYIIndRihM
         on1v5imbMcBqoeYxI5jAKMg3meVMYJrVx6JY8/HnVAIg028RWYo/psYJS9ZKFp7j5Idu
         Q8Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=hIW7x2FI3qJO/gOP+MbAmXw0rVrIy5rccMbHfiyi52g=;
        b=XqCfG5Ld0KrXHBmD+UCVAMTf77FPJWtLQpITRY9Q0BIwUue4NlOYUyyZDrjif8GYHA
         BND7PE4gXewLt4pe0P1CCGdYfnzEP/GxbH8iG8qpgxvFIFGdB5OiebWy25J+4djrw8lf
         PZhOmdOdDOAyD4CtdWpj6IVcpemIrqQiBCPy6g03z3d4kacDOeYPVRBgIeC/6bIOGh1+
         zZgEXD0ugCOcu2eUo7C+U03sYjHVMD0P1Z0gb1Alh2OPE0vgHmawAe4k5zT0fgcbvCnf
         Y9qF7JxjxqWiVVFDXheWS4GvLyb8t18/T42sGUOMfEc1n61Px0bqRzFPI4JcieT3D52I
         iWQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="dV/6aqwB";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hIW7x2FI3qJO/gOP+MbAmXw0rVrIy5rccMbHfiyi52g=;
        b=I4WnY9bnIbZxG0YRTX9Iaaw0y6dYacC/8p/ZI4qy/Vse4PmSD1H8px208hUiqwPKI6
         HLgZp9YP8z9PW85ut9T7VU967fAGknEfI+s6AbaOkJNBfGYwVXQtMhDRfMkWPcitkqCg
         9RQA3fdhGZLIh46OgvXCvhmY8+jpa4D/QM5nOMGRHkjfphBlB6HWiVSMFXEImayFQWhK
         QiKwZE1rFVMcHqnX5+Qb9/4diA/3rPAkwG0MN4VtnUlukvXB3i2FpW7jWLHHaUJR0Pln
         QXMBxHHT8hqGJIWAqmBDgMYFW2JZNOPZqUCJnxMmZdO7+0MPN+gaE32awXD8gRj4DoYB
         KgBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hIW7x2FI3qJO/gOP+MbAmXw0rVrIy5rccMbHfiyi52g=;
        b=gJX1J6gNJKMs89iAUFIMG68PHulByW+cQ+Tp7vJrK6SceHtSxa0T3aQPPjai4xpsuX
         hNxg+Otjfs7AxXRvqNh4OEJDjEW5IPyj0vmTH+yyn9bIHNEv/X5uo25FhmXvWZ8uug1p
         NEKDepsf/KkzA1efEeIOZA4HS4DJAjjsiTa1V9lAntDaoqvOMtFQPsdxpysJ2KbWdE9L
         Eo18IjAtk1fDLzaCg2vivsg4apifXvOaNrZsuETbUfQ5ydtgcd8Ps6k/SB2V2h08uW3P
         oSuUmrpwoJ/RcTEOIqBi70wEw0dGgQWTSHqDN42p8vAkX9+W2ADcr+k/ruX9Ol8yB5WH
         5enw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SeWVZ4yo3f3Opg8ks0CbCkptb6HRG48rGwELVwXtVRlnQJ8zC
	YSdrFbe2i0W1iaCBIF+0pu8=
X-Google-Smtp-Source: ABdhPJxP2OmHrLvyY3ZZ2O3NFvU2Fk7c5Sm5HcIezMwvrEUt/1jt219/KklSF+ZXHW1uVlMqqWtprg==
X-Received: by 2002:a05:6512:e9c:: with SMTP id bi28mr2802071lfb.498.1644321878834;
        Tue, 08 Feb 2022 04:04:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:22d1:: with SMTP id g17ls7734455lfu.2.gmail; Tue,
 08 Feb 2022 04:04:37 -0800 (PST)
X-Received: by 2002:a05:6512:22cd:: with SMTP id g13mr2798757lfu.191.1644321877820;
        Tue, 08 Feb 2022 04:04:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644321877; cv=none;
        d=google.com; s=arc-20160816;
        b=xRD9waebjG8pCLE98T4bhIgvKBODaU/1NSIitcecWXz7HvfGfzEXiWw7x/rl5113ji
         pNCQYqOQTVFk6x+OlRnfxL2Yx1ToKCanE8K30C9Tvlg07aN6bXLy1pmM0FqAocNp7SRo
         SgbHQYFau5MP4nf1YAHlSVHxSm1U67gMt23bV04UHyilsNlnFn83oWTyNVhGK/Myy1WF
         sorMhukwRsCHj9RJe2Ke9XK+FZ7y58QhW0no//et6SycvPjYw5uVUcHu+6ROqPT8A9Oh
         QO6ixSHr+pXTVL3joGNiNiMN1/7vLjJ7P+iyksE4UegKZQgdSVxOOQgLiaXRJVKUxXQ9
         GLKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=1Ynaws2GY/+Lh+Uv+SX/Dhjyk5BDPTdOy3iEgoGago0=;
        b=B/vvjUlh649bMul+Gw/OEWnMm39N0gnbrq4fVzCjjqNK65RISipzaL1Ps3cIC+J5gO
         rOWgRH2fpvJkaNGEV75ARmHAXSAgFTUXRJJhrJnwqcS6K7CxEEo5TxfhV3jjBpQ0voBR
         8NVU0EnPIs/cCfnnMUFgmu/1HXyYgVZn0y3iBTDWdaoFNE+gwmW/sNuuLDXcpw5god4A
         7uG7xeipKaySkr/W3Cpc0Jt4WQzmv+wXpdgyHdbIQjq7SJkhXj3cR7ehS+ovxRjXBI25
         0s/cfR3yogwai2C/wNcWpuJ18+5nk+/KjrmhVduoYQzC0nsvyuQtitmlyMJZSBsrPA2R
         PU9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="dV/6aqwB";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id x16si593487lfr.10.2022.02.08.04.04.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 04:04:37 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id p15so51600548ejc.7
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 04:04:37 -0800 (PST)
X-Received: by 2002:a17:907:7f0d:: with SMTP id qf13mr3417348ejc.446.1644321876465;
        Tue, 08 Feb 2022 04:04:36 -0800 (PST)
Received: from mail-ej1-f45.google.com (mail-ej1-f45.google.com. [209.85.218.45])
        by smtp.gmail.com with ESMTPSA id bv2sm4713827ejb.155.2022.02.08.04.04.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 04:04:35 -0800 (PST)
Received: by mail-ej1-f45.google.com with SMTP id fy20so2776968ejc.0
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 04:04:35 -0800 (PST)
X-Received: by 2002:a17:906:6a20:: with SMTP id qw32mr3393699ejc.40.1644321874965;
 Tue, 08 Feb 2022 04:04:34 -0800 (PST)
MIME-Version: 1.0
References: <20220208114541.2046909-1-ribalda@chromium.org> <20220208114541.2046909-3-ribalda@chromium.org>
In-Reply-To: <20220208114541.2046909-3-ribalda@chromium.org>
From: Ricardo Ribalda <ribalda@chromium.org>
Date: Tue, 8 Feb 2022 13:04:23 +0100
X-Gmail-Original-Message-ID: <CANiDSCsz_QBXfvXJ7o3KKeUoHckCcdx18tkM4vD4Y3x-2NDXrA@mail.gmail.com>
Message-ID: <CANiDSCsz_QBXfvXJ7o3KKeUoHckCcdx18tkM4vD4Y3x-2NDXrA@mail.gmail.com>
Subject: Re: [PATCH v4 3/6] thunderbolt: test: use NULL macros
To: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="dV/6aqwB";       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::62c
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Hi Daniel

On Tue, 8 Feb 2022 at 12:45, Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the NULL checks with the more specific and idiomatic NULL macros.
>
> Reviewed-by: Daniel Latypov <dlatypov@google.com>

Just realised that you ACKed by, not Reviewed-by. Will fix if I need
to send a v5.
Sorry about that

> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
> ---
>  drivers/thunderbolt/test.c | 130 ++++++++++++++++++-------------------
>  1 file changed, 65 insertions(+), 65 deletions(-)
>
> diff --git a/drivers/thunderbolt/test.c b/drivers/thunderbolt/test.c
> index 1f69bab236ee..f5bf8d659db4 100644
> --- a/drivers/thunderbolt/test.c
> +++ b/drivers/thunderbolt/test.c
> @@ -796,9 +796,9 @@ static void tb_test_path_not_connected(struct kunit *test)
>         up = &dev2->ports[9];
>
>         path = tb_path_alloc(NULL, down, 8, up, 8, 0, "PCIe Down");
> -       KUNIT_ASSERT_TRUE(test, path == NULL);
> +       KUNIT_ASSERT_NULL(test, path);
>         path = tb_path_alloc(NULL, down, 8, up, 8, 1, "PCIe Down");
> -       KUNIT_ASSERT_TRUE(test, path == NULL);
> +       KUNIT_ASSERT_NULL(test, path);
>  }
>
>  struct hop_expectation {
> @@ -847,7 +847,7 @@ static void tb_test_path_not_bonded_lane0(struct kunit *test)
>         up = &dev->ports[9];
>
>         path = tb_path_alloc(NULL, down, 8, up, 8, 0, "PCIe Down");
> -       KUNIT_ASSERT_TRUE(test, path != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, path);
>         KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
>         for (i = 0; i < ARRAY_SIZE(test_data); i++) {
>                 const struct tb_port *in_port, *out_port;
> @@ -909,7 +909,7 @@ static void tb_test_path_not_bonded_lane1(struct kunit *test)
>         out = &dev->ports[13];
>
>         path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
> -       KUNIT_ASSERT_TRUE(test, path != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, path);
>         KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
>         for (i = 0; i < ARRAY_SIZE(test_data); i++) {
>                 const struct tb_port *in_port, *out_port;
> @@ -989,7 +989,7 @@ static void tb_test_path_not_bonded_lane1_chain(struct kunit *test)
>         out = &dev3->ports[13];
>
>         path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
> -       KUNIT_ASSERT_TRUE(test, path != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, path);
>         KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
>         for (i = 0; i < ARRAY_SIZE(test_data); i++) {
>                 const struct tb_port *in_port, *out_port;
> @@ -1069,7 +1069,7 @@ static void tb_test_path_not_bonded_lane1_chain_reverse(struct kunit *test)
>         out = &host->ports[5];
>
>         path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
> -       KUNIT_ASSERT_TRUE(test, path != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, path);
>         KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
>         for (i = 0; i < ARRAY_SIZE(test_data); i++) {
>                 const struct tb_port *in_port, *out_port;
> @@ -1161,7 +1161,7 @@ static void tb_test_path_mixed_chain(struct kunit *test)
>         out = &dev4->ports[13];
>
>         path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
> -       KUNIT_ASSERT_TRUE(test, path != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, path);
>         KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
>         for (i = 0; i < ARRAY_SIZE(test_data); i++) {
>                 const struct tb_port *in_port, *out_port;
> @@ -1253,7 +1253,7 @@ static void tb_test_path_mixed_chain_reverse(struct kunit *test)
>         out = &host->ports[5];
>
>         path = tb_path_alloc(NULL, in, 9, out, 9, 1, "Video");
> -       KUNIT_ASSERT_TRUE(test, path != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, path);
>         KUNIT_ASSERT_EQ(test, path->path_length, ARRAY_SIZE(test_data));
>         for (i = 0; i < ARRAY_SIZE(test_data); i++) {
>                 const struct tb_port *in_port, *out_port;
> @@ -1297,7 +1297,7 @@ static void tb_test_tunnel_pcie(struct kunit *test)
>         down = &host->ports[8];
>         up = &dev1->ports[9];
>         tunnel1 = tb_tunnel_alloc_pci(NULL, up, down);
> -       KUNIT_ASSERT_TRUE(test, tunnel1 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel1);
>         KUNIT_EXPECT_EQ(test, tunnel1->type, TB_TUNNEL_PCI);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel1->src_port, down);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel1->dst_port, up);
> @@ -1312,7 +1312,7 @@ static void tb_test_tunnel_pcie(struct kunit *test)
>         down = &dev1->ports[10];
>         up = &dev2->ports[9];
>         tunnel2 = tb_tunnel_alloc_pci(NULL, up, down);
> -       KUNIT_ASSERT_TRUE(test, tunnel2 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel2);
>         KUNIT_EXPECT_EQ(test, tunnel2->type, TB_TUNNEL_PCI);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel2->src_port, down);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel2->dst_port, up);
> @@ -1349,7 +1349,7 @@ static void tb_test_tunnel_dp(struct kunit *test)
>         out = &dev->ports[13];
>
>         tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
> @@ -1395,7 +1395,7 @@ static void tb_test_tunnel_dp_chain(struct kunit *test)
>         out = &dev4->ports[14];
>
>         tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
> @@ -1445,7 +1445,7 @@ static void tb_test_tunnel_dp_tree(struct kunit *test)
>         out = &dev5->ports[13];
>
>         tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
> @@ -1510,7 +1510,7 @@ static void tb_test_tunnel_dp_max_length(struct kunit *test)
>         out = &dev12->ports[13];
>
>         tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DP);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, in);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, out);
> @@ -1566,7 +1566,7 @@ static void tb_test_tunnel_usb3(struct kunit *test)
>         down = &host->ports[12];
>         up = &dev1->ports[16];
>         tunnel1 = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel1 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel1);
>         KUNIT_EXPECT_EQ(test, tunnel1->type, TB_TUNNEL_USB3);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel1->src_port, down);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel1->dst_port, up);
> @@ -1581,7 +1581,7 @@ static void tb_test_tunnel_usb3(struct kunit *test)
>         down = &dev1->ports[17];
>         up = &dev2->ports[16];
>         tunnel2 = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel2 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel2);
>         KUNIT_EXPECT_EQ(test, tunnel2->type, TB_TUNNEL_USB3);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel2->src_port, down);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel2->dst_port, up);
> @@ -1628,7 +1628,7 @@ static void tb_test_tunnel_port_on_path(struct kunit *test)
>         out = &dev5->ports[13];
>
>         dp_tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, dp_tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dp_tunnel);
>
>         KUNIT_EXPECT_TRUE(test, tb_tunnel_port_on_path(dp_tunnel, in));
>         KUNIT_EXPECT_TRUE(test, tb_tunnel_port_on_path(dp_tunnel, out));
> @@ -1685,7 +1685,7 @@ static void tb_test_tunnel_dma(struct kunit *test)
>         port = &host->ports[1];
>
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
> @@ -1728,7 +1728,7 @@ static void tb_test_tunnel_dma_rx(struct kunit *test)
>         port = &host->ports[1];
>
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, -1, -1, 15, 2);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
> @@ -1765,7 +1765,7 @@ static void tb_test_tunnel_dma_tx(struct kunit *test)
>         port = &host->ports[1];
>
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 15, 2, -1, -1);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
> @@ -1811,7 +1811,7 @@ static void tb_test_tunnel_dma_chain(struct kunit *test)
>         nhi = &host->ports[7];
>         port = &dev2->ports[3];
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_EXPECT_EQ(test, tunnel->type, TB_TUNNEL_DMA);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->src_port, nhi);
>         KUNIT_EXPECT_PTR_EQ(test, tunnel->dst_port, port);
> @@ -1857,7 +1857,7 @@ static void tb_test_tunnel_dma_match(struct kunit *test)
>         port = &host->ports[1];
>
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 15, 1, 15, 1);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>
>         KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, 15, 1, 15, 1));
>         KUNIT_ASSERT_FALSE(test, tb_tunnel_match_dma(tunnel, 8, 1, 15, 1));
> @@ -1873,7 +1873,7 @@ static void tb_test_tunnel_dma_match(struct kunit *test)
>         tb_tunnel_free(tunnel);
>
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 15, 1, -1, -1);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, 15, 1, -1, -1));
>         KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, 15, -1, -1, -1));
>         KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, 1, -1, -1));
> @@ -1885,7 +1885,7 @@ static void tb_test_tunnel_dma_match(struct kunit *test)
>         tb_tunnel_free(tunnel);
>
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, -1, -1, 15, 11);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, -1, 15, 11));
>         KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, -1, 15, -1));
>         KUNIT_ASSERT_TRUE(test, tb_tunnel_match_dma(tunnel, -1, -1, -1, 11));
> @@ -1910,7 +1910,7 @@ static void tb_test_credit_alloc_legacy_not_bonded(struct kunit *test)
>         down = &host->ports[8];
>         up = &dev->ports[9];
>         tunnel = tb_tunnel_alloc_pci(NULL, up, down);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
>
>         path = tunnel->paths[0];
> @@ -1943,7 +1943,7 @@ static void tb_test_credit_alloc_legacy_bonded(struct kunit *test)
>         down = &host->ports[8];
>         up = &dev->ports[9];
>         tunnel = tb_tunnel_alloc_pci(NULL, up, down);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
>
>         path = tunnel->paths[0];
> @@ -1976,7 +1976,7 @@ static void tb_test_credit_alloc_pcie(struct kunit *test)
>         down = &host->ports[8];
>         up = &dev->ports[9];
>         tunnel = tb_tunnel_alloc_pci(NULL, up, down);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
>
>         path = tunnel->paths[0];
> @@ -2010,7 +2010,7 @@ static void tb_test_credit_alloc_dp(struct kunit *test)
>         out = &dev->ports[14];
>
>         tunnel = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)3);
>
>         /* Video (main) path */
> @@ -2053,7 +2053,7 @@ static void tb_test_credit_alloc_usb3(struct kunit *test)
>         down = &host->ports[12];
>         up = &dev->ports[16];
>         tunnel = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
>
>         path = tunnel->paths[0];
> @@ -2087,7 +2087,7 @@ static void tb_test_credit_alloc_dma(struct kunit *test)
>         port = &dev->ports[3];
>
>         tunnel = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
> -       KUNIT_ASSERT_TRUE(test, tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel);
>         KUNIT_ASSERT_EQ(test, tunnel->npaths, (size_t)2);
>
>         /* DMA RX */
> @@ -2141,7 +2141,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
>          * remaining 1 and then we run out of buffers.
>          */
>         tunnel1 = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
> -       KUNIT_ASSERT_TRUE(test, tunnel1 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel1);
>         KUNIT_ASSERT_EQ(test, tunnel1->npaths, (size_t)2);
>
>         path = tunnel1->paths[0];
> @@ -2159,7 +2159,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
>         KUNIT_EXPECT_EQ(test, path->hops[1].initial_credits, 14U);
>
>         tunnel2 = tb_tunnel_alloc_dma(NULL, nhi, port, 9, 2, 9, 2);
> -       KUNIT_ASSERT_TRUE(test, tunnel2 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel2);
>         KUNIT_ASSERT_EQ(test, tunnel2->npaths, (size_t)2);
>
>         path = tunnel2->paths[0];
> @@ -2177,7 +2177,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
>         KUNIT_EXPECT_EQ(test, path->hops[1].initial_credits, 1U);
>
>         tunnel3 = tb_tunnel_alloc_dma(NULL, nhi, port, 10, 3, 10, 3);
> -       KUNIT_ASSERT_TRUE(test, tunnel3 == NULL);
> +       KUNIT_ASSERT_NULL(test, tunnel3);
>
>         /*
>          * Release the first DMA tunnel. That should make 14 buffers
> @@ -2186,7 +2186,7 @@ static void tb_test_credit_alloc_dma_multiple(struct kunit *test)
>         tb_tunnel_free(tunnel1);
>
>         tunnel3 = tb_tunnel_alloc_dma(NULL, nhi, port, 10, 3, 10, 3);
> -       KUNIT_ASSERT_TRUE(test, tunnel3 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, tunnel3);
>
>         path = tunnel3->paths[0];
>         KUNIT_ASSERT_EQ(test, path->path_length, 2);
> @@ -2216,7 +2216,7 @@ static struct tb_tunnel *TB_TEST_PCIE_TUNNEL(struct kunit *test,
>         down = &host->ports[8];
>         up = &dev->ports[9];
>         pcie_tunnel = tb_tunnel_alloc_pci(NULL, up, down);
> -       KUNIT_ASSERT_TRUE(test, pcie_tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, pcie_tunnel);
>         KUNIT_ASSERT_EQ(test, pcie_tunnel->npaths, (size_t)2);
>
>         path = pcie_tunnel->paths[0];
> @@ -2246,7 +2246,7 @@ static struct tb_tunnel *TB_TEST_DP_TUNNEL1(struct kunit *test,
>         in = &host->ports[5];
>         out = &dev->ports[13];
>         dp_tunnel1 = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, dp_tunnel1 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dp_tunnel1);
>         KUNIT_ASSERT_EQ(test, dp_tunnel1->npaths, (size_t)3);
>
>         path = dp_tunnel1->paths[0];
> @@ -2283,7 +2283,7 @@ static struct tb_tunnel *TB_TEST_DP_TUNNEL2(struct kunit *test,
>         in = &host->ports[6];
>         out = &dev->ports[14];
>         dp_tunnel2 = tb_tunnel_alloc_dp(NULL, in, out, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, dp_tunnel2 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dp_tunnel2);
>         KUNIT_ASSERT_EQ(test, dp_tunnel2->npaths, (size_t)3);
>
>         path = dp_tunnel2->paths[0];
> @@ -2320,7 +2320,7 @@ static struct tb_tunnel *TB_TEST_USB3_TUNNEL(struct kunit *test,
>         down = &host->ports[12];
>         up = &dev->ports[16];
>         usb3_tunnel = tb_tunnel_alloc_usb3(NULL, up, down, 0, 0);
> -       KUNIT_ASSERT_TRUE(test, usb3_tunnel != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, usb3_tunnel);
>         KUNIT_ASSERT_EQ(test, usb3_tunnel->npaths, (size_t)2);
>
>         path = usb3_tunnel->paths[0];
> @@ -2350,7 +2350,7 @@ static struct tb_tunnel *TB_TEST_DMA_TUNNEL1(struct kunit *test,
>         nhi = &host->ports[7];
>         port = &dev->ports[3];
>         dma_tunnel1 = tb_tunnel_alloc_dma(NULL, nhi, port, 8, 1, 8, 1);
> -       KUNIT_ASSERT_TRUE(test, dma_tunnel1 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dma_tunnel1);
>         KUNIT_ASSERT_EQ(test, dma_tunnel1->npaths, (size_t)2);
>
>         path = dma_tunnel1->paths[0];
> @@ -2380,7 +2380,7 @@ static struct tb_tunnel *TB_TEST_DMA_TUNNEL2(struct kunit *test,
>         nhi = &host->ports[7];
>         port = &dev->ports[3];
>         dma_tunnel2 = tb_tunnel_alloc_dma(NULL, nhi, port, 9, 2, 9, 2);
> -       KUNIT_ASSERT_TRUE(test, dma_tunnel2 != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dma_tunnel2);
>         KUNIT_ASSERT_EQ(test, dma_tunnel2->npaths, (size_t)2);
>
>         path = dma_tunnel2->paths[0];
> @@ -2496,50 +2496,50 @@ static void tb_test_property_parse(struct kunit *test)
>         struct tb_property *p;
>
>         dir = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
> -       KUNIT_ASSERT_TRUE(test, dir != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dir);
>
>         p = tb_property_find(dir, "foo", TB_PROPERTY_TYPE_TEXT);
>         KUNIT_ASSERT_TRUE(test, !p);
>
>         p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_TEXT);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_STREQ(test, p->value.text, "Apple Inc.");
>
>         p = tb_property_find(dir, "vendorid", TB_PROPERTY_TYPE_VALUE);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa27);
>
>         p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_TEXT);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_STREQ(test, p->value.text, "Macintosh");
>
>         p = tb_property_find(dir, "deviceid", TB_PROPERTY_TYPE_VALUE);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_EQ(test, p->value.immediate, 0xa);
>
>         p = tb_property_find(dir, "missing", TB_PROPERTY_TYPE_DIRECTORY);
>         KUNIT_ASSERT_TRUE(test, !p);
>
>         p = tb_property_find(dir, "network", TB_PROPERTY_TYPE_DIRECTORY);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>
>         network_dir = p->value.dir;
>         KUNIT_EXPECT_TRUE(test, uuid_equal(network_dir->uuid, &network_dir_uuid));
>
>         p = tb_property_find(network_dir, "prtcid", TB_PROPERTY_TYPE_VALUE);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_EQ(test, p->value.immediate, 0x1);
>
>         p = tb_property_find(network_dir, "prtcvers", TB_PROPERTY_TYPE_VALUE);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_EQ(test, p->value.immediate, 0x1);
>
>         p = tb_property_find(network_dir, "prtcrevs", TB_PROPERTY_TYPE_VALUE);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_EQ(test, p->value.immediate, 0x1);
>
>         p = tb_property_find(network_dir, "prtcstns", TB_PROPERTY_TYPE_VALUE);
> -       KUNIT_ASSERT_TRUE(test, p != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, p);
>         KUNIT_EXPECT_EQ(test, p->value.immediate, 0x0);
>
>         p = tb_property_find(network_dir, "deviceid", TB_PROPERTY_TYPE_VALUE);
> @@ -2558,7 +2558,7 @@ static void tb_test_property_format(struct kunit *test)
>         int ret, i;
>
>         dir = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
> -       KUNIT_ASSERT_TRUE(test, dir != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dir);
>
>         ret = tb_property_format_dir(dir, NULL, 0);
>         KUNIT_ASSERT_EQ(test, ret, ARRAY_SIZE(root_directory));
> @@ -2566,7 +2566,7 @@ static void tb_test_property_format(struct kunit *test)
>         block_len = ret;
>
>         block = kunit_kzalloc(test, block_len * sizeof(u32), GFP_KERNEL);
> -       KUNIT_ASSERT_TRUE(test, block != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, block);
>
>         ret = tb_property_format_dir(dir, block, block_len);
>         KUNIT_EXPECT_EQ(test, ret, 0);
> @@ -2584,10 +2584,10 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
>         int n1, n2, i;
>
>         if (d1->uuid) {
> -               KUNIT_ASSERT_TRUE(test, d2->uuid != NULL);
> +               KUNIT_ASSERT_NOT_NULL(test, d2->uuid);
>                 KUNIT_ASSERT_TRUE(test, uuid_equal(d1->uuid, d2->uuid));
>         } else {
> -               KUNIT_ASSERT_TRUE(test, d2->uuid == NULL);
> +               KUNIT_ASSERT_NULL(test, d2->uuid);
>         }
>
>         n1 = 0;
> @@ -2606,9 +2606,9 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
>         p2 = NULL;
>         for (i = 0; i < n1; i++) {
>                 p1 = tb_property_get_next(d1, p1);
> -               KUNIT_ASSERT_TRUE(test, p1 != NULL);
> +               KUNIT_ASSERT_NOT_NULL(test, p1);
>                 p2 = tb_property_get_next(d2, p2);
> -               KUNIT_ASSERT_TRUE(test, p2 != NULL);
> +               KUNIT_ASSERT_NOT_NULL(test, p2);
>
>                 KUNIT_ASSERT_STREQ(test, &p1->key[0], &p2->key[0]);
>                 KUNIT_ASSERT_EQ(test, p1->type, p2->type);
> @@ -2616,14 +2616,14 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
>
>                 switch (p1->type) {
>                 case TB_PROPERTY_TYPE_DIRECTORY:
> -                       KUNIT_ASSERT_TRUE(test, p1->value.dir != NULL);
> -                       KUNIT_ASSERT_TRUE(test, p2->value.dir != NULL);
> +                       KUNIT_ASSERT_NOT_NULL(test, p1->value.dir);
> +                       KUNIT_ASSERT_NOT_NULL(test, p2->value.dir);
>                         compare_dirs(test, p1->value.dir, p2->value.dir);
>                         break;
>
>                 case TB_PROPERTY_TYPE_DATA:
> -                       KUNIT_ASSERT_TRUE(test, p1->value.data != NULL);
> -                       KUNIT_ASSERT_TRUE(test, p2->value.data != NULL);
> +                       KUNIT_ASSERT_NOT_NULL(test, p1->value.data);
> +                       KUNIT_ASSERT_NOT_NULL(test, p2->value.data);
>                         KUNIT_ASSERT_TRUE(test,
>                                 !memcmp(p1->value.data, p2->value.data,
>                                         p1->length * 4)
> @@ -2631,8 +2631,8 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
>                         break;
>
>                 case TB_PROPERTY_TYPE_TEXT:
> -                       KUNIT_ASSERT_TRUE(test, p1->value.text != NULL);
> -                       KUNIT_ASSERT_TRUE(test, p2->value.text != NULL);
> +                       KUNIT_ASSERT_NOT_NULL(test, p1->value.text);
> +                       KUNIT_ASSERT_NOT_NULL(test, p2->value.text);
>                         KUNIT_ASSERT_STREQ(test, p1->value.text, p2->value.text);
>                         break;
>
> @@ -2654,10 +2654,10 @@ static void tb_test_property_copy(struct kunit *test)
>         int ret, i;
>
>         src = tb_property_parse_dir(root_directory, ARRAY_SIZE(root_directory));
> -       KUNIT_ASSERT_TRUE(test, src != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, src);
>
>         dst = tb_property_copy_dir(src);
> -       KUNIT_ASSERT_TRUE(test, dst != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, dst);
>
>         /* Compare the structures */
>         compare_dirs(test, src, dst);
> @@ -2667,7 +2667,7 @@ static void tb_test_property_copy(struct kunit *test)
>         KUNIT_ASSERT_EQ(test, ret, ARRAY_SIZE(root_directory));
>
>         block = kunit_kzalloc(test, sizeof(root_directory), GFP_KERNEL);
> -       KUNIT_ASSERT_TRUE(test, block != NULL);
> +       KUNIT_ASSERT_NOT_NULL(test, block);
>
>         ret = tb_property_format_dir(dst, block, ARRAY_SIZE(root_directory));
>         KUNIT_EXPECT_TRUE(test, !ret);
> --
> 2.35.0.263.gb82422642f-goog
>


-- 
Ricardo Ribalda

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiDSCsz_QBXfvXJ7o3KKeUoHckCcdx18tkM4vD4Y3x-2NDXrA%40mail.gmail.com.
