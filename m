Return-Path: <kasan-dev+bncBDUNBGN3R4KRBBFAV2PAMGQEANVBAJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 56D4C6764D8
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:02 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id y10-20020a62640a000000b0058de08b3336sf3337657pfb.4
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285060; cv=pass;
        d=google.com; s=arc-20160816;
        b=wI473mjM/Nmz5Ue3Ez9rR2pfynul+77H/fK05oQJGJVHvBICf6XQUYxr55aFBhY/SI
         OnAQ4FD9S2SyAkpxszVQOuf0X06yW9zl7/Nn1diAAdViD6zs+tB7yt2ty5r3EsynITzk
         x01PaxLj4rsRLdQrpH4A2TTzdQwjKw5WwAGi1ALs5N75zgLXdxQKZMvEhr9V9g3FMxYt
         6QlYnRYs0hp+M5y/1RReHWD0yC4sWVdo8RilNmWkUqtHzJnz2PRve97HG0KL1GMEn7dy
         9CdhBrPLCZCTxCwMkTmFufrGscWs122XpOHlsc1yQFodEBvZS6alo8ufbiJ4Y05ko5ez
         1m8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/SvvYcEa4+y2nu0TlSB7z6HwUfyCaLVwYlaa/gF4l7s=;
        b=s4FA9Rp+qfYBGl8X14wpkZ3d1UAk2uTs4eQIu6Zh90uTImZZ8t+d0pSongaeFzFbLg
         QgjGhA4RFqy/vcqhxVptv7QsHt6ugOtVEshxdZxt5nzG1Z1IlidlHXrPndu7Cy7hJqKk
         ssu2RQNArJ6NEe/l7kDDTQJUOEccSnU6cCl27Z1poj8Qa74lCi5R8ULePzaNB3p96sO4
         c5Aj2MAm/13Jm03jZTchSMC4HZfpO4HXnR/9iIB0v40N9ZrOVj7J1x6CVSQlhCxIMXA0
         AETpMOmI5NNqP5ztpnjkZuxGnTLE8mDUNYzQCJ9myZn9SfZtbaDFIi5SkusDlojwd0gk
         pHNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=HCk2PP6U;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/SvvYcEa4+y2nu0TlSB7z6HwUfyCaLVwYlaa/gF4l7s=;
        b=WHLBK/aFK4qu7tbf4R6pIgLeUSxKVS2V2+tyYZVCaMYqoL6//gTRme/aQo/T4K5ULL
         /O3emjATYMWn3zysPyEUhvERfbiLJKlL+BBXranoHCjlOTw0GWJ8xIFqWQr7dPBNNG69
         F00KFku85bfiCoHfwL43LrpCdO6xdrd+NLAHaX7pde5CBRqskOTIC3aMgMX2FBVVVXJt
         8f6y0h1AktcY2JO++N20Wsko00K9LfL7798eMJOUh0WGpVIVSK+kftPbtacJpFb3YqoH
         zFkskROoUEqM1nRzYuv9ezklMjkQB6umjX486nrqrIrQfXOA0AhzTtKe6xt8RhSgOmps
         OZqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=/SvvYcEa4+y2nu0TlSB7z6HwUfyCaLVwYlaa/gF4l7s=;
        b=FntH/ukIE9LA0uMlj+nW+2j58Wpmqt+GXZVYdeF8QfSfFfDplZqaHJQuHM6rWbJktx
         u3Is41adtWrYvJxdgeTL96CZeAmO0HPSE1XoZ5vXrSOSKy3lB+Jv750xzFhTbc492yiO
         CWVE42Z5Kafodb0FFQzP9Fx1O79VAu9yJ8ImtGFg/PLxO8XqIAsGztM7CWNXpsTGvgdt
         b2O6SMHcvrb2QIc2EmO4+Sds49bhsDKWk1fhw07opo4MMnILCauNSmzaSWyaxaD9kjLZ
         AAIgQthjq5GWVRuzfzLJDUDGEQEu7ZjkZnnaYkikS4796dKLXiA5+PcXly+XaMzGagHG
         mJTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krtPgVbWaaaMatmeJqPeTyuogEnQ7m1+Zr8sXMKG8aOO8aOuiuI
	azVxIZMR4E9CV+/1nCcpqo4=
X-Google-Smtp-Source: AMrXdXtsiKn0Uwgvye/AbLl9Vj0i4pu611tJ5XE/9y7V0c1rg8HILaeOKupXgIQvJYDgTLIsZ4eoSw==
X-Received: by 2002:a17:90a:9b02:b0:226:2124:ef60 with SMTP id f2-20020a17090a9b0200b002262124ef60mr2608803pjp.201.1674285060395;
        Fri, 20 Jan 2023 23:11:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8e54:0:b0:581:bfab:c813 with SMTP id d20-20020aa78e54000000b00581bfabc813ls1904537pfr.7.-pod-prod-gmail;
 Fri, 20 Jan 2023 23:10:59 -0800 (PST)
X-Received: by 2002:a05:6a00:328b:b0:577:1c59:a96c with SMTP id ck11-20020a056a00328b00b005771c59a96cmr20047417pfb.2.1674285059451;
        Fri, 20 Jan 2023 23:10:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285059; cv=none;
        d=google.com; s=arc-20160816;
        b=Tw/U5WWOVQacsmpezZYYtPUJFnMaZfV/SnLu7Rk25NUc/z3U1+NjewFgV5iK7JF+qo
         DxHMsV1qdWZSNszOETL7ATjBxoBMBrNu4fEt7kVkWDB1MaBDepr7gWNcWxMD6bisU8kk
         1bbLKcd5k9DpUYgufueypq6rKRMExzDV1sbYkDWZl4EVXEtLM/Gdmfi44TBRg+HWsxWy
         pGI4hfZ+Nf1U8DHgcD5ZczM+tjNZP+qgJddi2oIUObguUEn2jyeNb6N6QLTkyi5YTJJW
         AkTB0eirZW8192iQ83Gf3doo2sDNy2xSl+C0VVwcVRLGKEeTmMdGBcatw2OoUTeeZhaf
         3rjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=XxN/g06gXKKOzUk9/hxK/873YDVkeAm3rSW7JQGJyyY=;
        b=xarHtENwfHw7P1xbY87dMgqBhTYOgA1QROpQLwdqtsK5zNCp9oWmqEaMIuh/sODiuh
         OP+a/TBcIU/+zzQBOgtnQJi3Nfw5BcY9XLWVp0DZtetVRiQ1qcZQzEKeQ0QyrYQB+P2V
         4HC68k1fxxeHhqjLPuQuv4yK06W05FW6W4uVySVARLjG98DwmbMtnSlqgSrNT0VK7dOl
         Q6duXR58XbjI60fsPiNvz9t8JnYp1AWfBJs7ERT3Jy6xwDSDQa3eKGA3f5YGkLpCmf+G
         MqXOsR9G+pP8FD/bU7lQCS8fP2Yv2SNoAaO9VP+8XT34xxaeXAhIIJltHLN9bdTrCsdw
         ZKHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=HCk2PP6U;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id q10-20020a056a0002aa00b0058e08791ba4si584710pfs.4.2023.01.20.23.10.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:10:59 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81d-00DTm3-SS; Sat, 21 Jan 2023 07:10:54 +0000
From: Christoph Hellwig <hch@lst.de>
To: Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: cleanup vfree and vunmap
Date: Sat, 21 Jan 2023 08:10:41 +0100
Message-Id: <20230121071051.1143058-1-hch@lst.de>
X-Mailer: git-send-email 2.39.0
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=HCk2PP6U;
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
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

Hi all,

this little series untangles the vfree and vunmap code path a bit.

For the KASAN maintainers:  the interesting patch re KASAN is patch 8.

Note that it depends on 'Revert "remoteproc: qcom_q6v5_mss: map/unmap metadata
region before/after use"' in linux-next.

Changes since v1:
 - drop an extra WARN_ON

Diffstat:
 vmalloc.c |  304 +++++++++++++++++++++++++++-----------------------------------
 1 file changed, 134 insertions(+), 169 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-1-hch%40lst.de.
