Return-Path: <kasan-dev+bncBDAMBG7U3IMRBTUQUS6AMGQELGEYAWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id B2E74A13AD4
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2025 14:23:27 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-468f80df8casf18942851cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2025 05:23:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1737033806; cv=pass;
        d=google.com; s=arc-20240605;
        b=iZO4FhDOvGU5mUvTPo2YBo2RF3hPLO+xg922SS0ZUtcIOmTvgZQud48S3zn3HMTFeC
         5DK3vxNAP9fYbkWrCCYlYTDCmMUAURxfnOZ207tvrNFULFL7aHSiKegk5Rtm+OzucWhU
         1ceHwF6CSLmjPq0gsC498neYAESlK8rvTtsbW7J7Qh/SUPDCAVQMgIpnSqXu4uFvwLZ4
         5V+ztn3YOyggG0Tir0WtTxr0HgqQ9VihWu+Ec8xTrF0zXPuzcgPNdwVuuOWwqQK7g8vD
         gxttsCMY1qbfvnxnqakrE/fJTLxKGIBpc6hGmTyPMpS/ZgxEkBWX6LRdFXpmNJEoixaF
         xyYw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:mime-version:date
         :message-id:sender:dkim-signature;
        bh=sqq4ZxnLURpK7iyiyGOgE90ThMpNIqkIz+oymtUimMY=;
        fh=U7hhMNUjNB7nrW+y9cRagJY75ndD0vI40+iuEJ6BVt4=;
        b=RDQGcAvshBOvN8fyYAef8ZAWnGO1aqOuWV+MemeOyH5ydzKOgBGpWvxXzJVYkPGRl2
         wUrZIHcFlcTxXSNv6qK8z5Zka/L5xO1YN/JMAOAu3B2siOLgyZGrybhm97QnvawsH9Jn
         /eRegd8uwN5NUKrXjJuYqG5V7iSwDa6X093t0Skm5ExRrBiGThwHOeYZgCPAdougJ9LC
         S8hb6BUsJjuTAPtZsEgimX8FiMl3gpfL/K4sb2sdYo9Z6CDNtQ0GPNtnMttwdNTlzIoM
         3iU85HhbPHvO97OtRdiqn2zuP5rAbd3I9hvNCqX6rPd3jguLUBZK6aH+d0OEvWvCt6gI
         /j/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@connect.bigfatlinks.tech header.s=zmail header.b=Z2eI6Bnl;
       arc=pass (i=1 spf=pass spfdomain=connect.bigfatlinks.tech dkim=pass dkdomain=connect.bigfatlinks.tech dmarc=pass fromdomain=connect.bigfatlinks.tech>);
       spf=pass (google.com: domain of kelsea@connect.bigfatlinks.tech designates 136.143.169.11 as permitted sender) smtp.mailfrom=kelsea@connect.bigfatlinks.tech;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=connect.bigfatlinks.tech
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737033806; x=1737638606; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sqq4ZxnLURpK7iyiyGOgE90ThMpNIqkIz+oymtUimMY=;
        b=PzFHM5TPUmHrpjVkm0L4+X2E3rS+aycEs7qMD1Y9zWpsDi1kCn5JqOoERlBbRNY3cf
         UDU6HRz6vcMW1imckGbWtOxY7+gzXdUKXE2PEqgXEEM6CNn3nb7Yvln2wdQEhqNOite8
         khrm/6xCKRiq63IOI7CZfhBJrv+6hlnKv8pNG+LwL/Yk0DkX22mW0gtKmVT2zQXrdbmk
         rbC/B7n056Syz/nhHkHsV+uXjbQ9rBSlRPn9vIYu+fRi1d+tYkuVD71mEM2Hz2h3+2FH
         3p5FqWDukqcfBDHkLyVsNY6ilKh3Mj7J0fZSjCRJ6/Ag82HfYqOiYd3TZO/u9Xp9hBkc
         O1vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737033806; x=1737638606;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sqq4ZxnLURpK7iyiyGOgE90ThMpNIqkIz+oymtUimMY=;
        b=SsKVGh26qEHxUq+HaHDVfyfKDVcvOM0SxESRmBz4c5ugPSHSJGxAZvdYwMmiIu/PrD
         keQMN+Ls/pfyPDIag7M2Ia01HSxPhHW2dZOIXLjdqanwKoO/ZZKdlgFAepBi2c/gNpB3
         itALn0v7HEtqHz6e0ZLK/hzPzZcVP8xK/afS01JiA6e4f3YmQQiv9A3Mc/+x242x98VP
         QYCXYsjISbpqUA9I1vCtyfNddrwmFFaOu5tOTJGwUD9NIbDYBmhrH1DTxL5XJisJTwRw
         u9pkXTnYm2ENzv2SACkBQxq4bGOkcLHNhrwybM6POQbLeFAPrDsIQWPn9Fczlar2/GU5
         vqxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCW31WGOKHNxkcls6cF6y6WvGYET/69JbkZTUREScXkzj9JYDfZH4QFV/SKYzbgVcIw1fycPZg==@lfdr.de
X-Gm-Message-State: AOJu0YxosHf7s4laXURO9kirgFSrO1IYQNHGAPtv7mAvlKPq4reR1mGI
	qQn8IGqvchadTrguRwdTHCve2D6ICav0LjhIbCFbG070w0duWEN2
X-Google-Smtp-Source: AGHT+IHlN8/lo7GDYX1Kdy1HoaLX8y0iJmaGfoTDjRoq6av7zkCW7D//wSIw/tMPWvsOBlZci/GB4Q==
X-Received: by 2002:a05:622a:1a86:b0:467:7b76:5957 with SMTP id d75a77b69052e-46c7107dcf1mr534749191cf.2.1737033806434;
        Thu, 16 Jan 2025 05:23:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:5e11:b0:467:8ca0:7f4b with SMTP id
 d75a77b69052e-46e02e2c3d4ls19380191cf.2.-pod-prod-01-us; Thu, 16 Jan 2025
 05:23:25 -0800 (PST)
X-Received: by 2002:a05:622a:130c:b0:467:7557:5fbb with SMTP id d75a77b69052e-46c710aac66mr493386541cf.27.1737033805683;
        Thu, 16 Jan 2025 05:23:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737033805; cv=pass;
        d=google.com; s=arc-20240605;
        b=YdpMHlQiTiCEWRrjV9x5TF3yc35XElFQtQl/CnTnPi4s5RmwWawEAInmXxBoOOUCw+
         RIZg7TDOiDQCbtJmAblxrvNod1X2oU84/RSbzx+qDyZIhu5NVxmvzwVWKRYqEWlCbI02
         cO/d2WKHrOeNe5/wsTkURdN9p6xZAVjQDpshVLJFWZW0KoZ/6ENEe4HOb8oa9vrfCo9S
         kx9+CoOXtolote9IpIBjSYG0F8Km5NBeUdnD18dTpJW0LH7mLgwVbQSFXmAA5fjK1zJi
         ew5Qdpo6/u8Ry3LvV3dReWZmWPwO7PWOXIWe3pu6fDPNjcDl6B5anmPeNhZD7TBjTnfL
         BYPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:mime-version:date:message-id:dkim-signature;
        bh=q84Wk+Y2yaJY+HAjsm6j2Mx701S2j4pFFPlKDQBgFqE=;
        fh=7EpxGOxsjrGTFAhe1ll5ZROWTZ1LOwDHCWT1D30uCI0=;
        b=F27MFanWSJCaCt6TLq/zct97wfpdnsdoyWLQrYZ4DIIfSYT3zk9IfmXqr8caz8D6+R
         4jd0MF/wlSl2fSRVOIrziMLlQrtafE8zVVvFcBWjgzp7SZvUZqAy3bVuzYXW45i4Yfb+
         ++vNRj2wQGvENjReJ0q3AQgMIj8kwUneMntRHpQSa73ix02yMocD0sQOFFEFTEJcVYOs
         s+l7RcqY94ioxZ7t57dHGb+xAKh6vZbknTkIG038j7y12CiG6Azg8yJBGK/uS5CURBXF
         lHagpTmo/SJjlrnXEs8jpkVX6vx9LmmqHaJNsNH/VE0Khf3ottLN1wWAPBiTvgH26EDO
         ageg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@connect.bigfatlinks.tech header.s=zmail header.b=Z2eI6Bnl;
       arc=pass (i=1 spf=pass spfdomain=connect.bigfatlinks.tech dkim=pass dkdomain=connect.bigfatlinks.tech dmarc=pass fromdomain=connect.bigfatlinks.tech>);
       spf=pass (google.com: domain of kelsea@connect.bigfatlinks.tech designates 136.143.169.11 as permitted sender) smtp.mailfrom=kelsea@connect.bigfatlinks.tech;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=connect.bigfatlinks.tech
Received: from sender-op-o11.zoho.eu (sender-op-o11.zoho.eu. [136.143.169.11])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-46c873b8d86si6283631cf.3.2025.01.16.05.23.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Jan 2025 05:23:25 -0800 (PST)
Received-SPF: pass (google.com: domain of kelsea@connect.bigfatlinks.tech designates 136.143.169.11 as permitted sender) client-ip=136.143.169.11;
ARC-Seal: i=1; a=rsa-sha256; t=1737033803; cv=none; 
	d=zohomail.eu; s=zohoarc; 
	b=XLvrj9bTQxRuZH2xEy5PNuN0pV6ic+xFbnmb6341iXnuyDzkJ18QqG4FGnY1RcYTIOztELRk2N1qK17Phso+0F+ba86yOINqdv+UPrNLsR1HymN+Dul3SyZ3l5EfTH0b5C8cSEe4So+nsJ+TgJcj0d+QveaC4tpGR0O7lgohzy8=
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=zohomail.eu; s=zohoarc; 
	t=1737033803; h=Content-Type:Date:Date:From:From:MIME-Version:Message-ID:Subject:Subject:To:To:Message-Id:Reply-To:Cc; 
	bh=q84Wk+Y2yaJY+HAjsm6j2Mx701S2j4pFFPlKDQBgFqE=; 
	b=EBwc89ioCi8g+AXY95IDQytffKVKIlZXQ/HkPxsS2KyGmP2PnW3R1fiWUkr6Z6A77lAIFkurw2btHHIEDhs5sM5ZXtj84gwwkKDgYkkQYdh7jIjlBpinzLmM5AhBZNk65rZfVqd5+bDh7TPJPsnupTn5UxWByyJk17VFNpFo5XU=
ARC-Authentication-Results: i=1; mx.zohomail.eu;
	dkim=pass  header.i=connect.bigfatlinks.tech;
	spf=pass  smtp.mailfrom=kelsea@connect.bigfatlinks.tech;
	dmarc=pass header.from=<kelsea@connect.bigfatlinks.tech>
Received: by mx.zoho.eu with SMTPS id 17370338002231015.5269109530692;
	Thu, 16 Jan 2025 14:23:20 +0100 (CET)
Message-id: <9hmmszvh2dngpt2feoukg6038.D73J3ACG9X04@connect.bigfatlinks.tech>
Date: Thu, 16 Jan 2025 13:23:17 +0000
Mime-Version: 1.0
x-nylas-send-v3: true
Subject: Your Backlink on gearrice.com
From: "Big Fat Links" <kelsea@connect.bigfatlinks.tech>
To: "Unknown" <kasan-dev@googlegroups.com>,
Content-Type: multipart/related;
 boundary=9a65524b43b4207fe2dfc111bdb37c1307de5f6a5746329819bf442b2a31
X-ZohoMailClient: External
X-Original-Sender: kelsea@connect.bigfatlinks.tech
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@connect.bigfatlinks.tech header.s=zmail header.b=Z2eI6Bnl;
       arc=pass (i=1 spf=pass spfdomain=connect.bigfatlinks.tech dkim=pass
 dkdomain=connect.bigfatlinks.tech dmarc=pass fromdomain=connect.bigfatlinks.tech>);
       spf=pass (google.com: domain of kelsea@connect.bigfatlinks.tech
 designates 136.143.169.11 as permitted sender) smtp.mailfrom=kelsea@connect.bigfatlinks.tech;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=connect.bigfatlinks.tech
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

--9a65524b43b4207fe2dfc111bdb37c1307de5f6a5746329819bf442b2a31
Content-Type: multipart/alternative;
	boundary="altpart-9a65524b43b4207fe2dfc111bdb37c1307de5f6a5746329819bf442b2a31"

--altpart-9a65524b43b4207fe2dfc111bdb37c1307de5f6a5746329819bf442b2a31
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="UTF-8"

Hi

As you previously acquired backlinks on the domain=C2=A0gearrice.com, on=C2=
=A0Nov 24th 2024, for your domain=C2=A0googlegroups.com.

We found your domain, we found your backlinks, and we can find you better b=
acklinks to improve your Google rankings.

Our team at Big Fat Links is here to provide a dedicated service. We delive=
r high-quality backlinks that help drive your search terms to the top of th=
e search engines' rankings, and we ensure our backlinks drive the traffic t=
hat's important to you, traffic that has buying/converting intent, and solu=
tions that help you deliver your online goals.

We believe in quality over quantity and in exceeding your expectations. We =
back that up with a money-back guarantee. !

If you want a service from reputable experts who have been in the industry =
for many years, working with over 1,500 clients, then drop me a line today,=
 or visit Bigfatlinks.com

Thanks

Big Fat Links
Big Fat Links Ltd
1 mann island, wilmslow, cheshire east, united kingdom

If you don't want to hear from me again, please let me know.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9=
hmmszvh2dngpt2feoukg6038.D73J3ACG9X04%40connect.bigfatlinks.tech.

--altpart-9a65524b43b4207fe2dfc111bdb37c1307de5f6a5746329819bf442b2a31
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="UTF-8"

<div dir=3D"ltr"><div>Hi=C2=A0</div><div><br></div><div>As you previously a=
cquired backlinks on the domain=C2=A0gearrice.com, on=C2=A0Nov 24th 2024, f=
or your domain=C2=A0googlegroups.com.</div><div><br></div><div>We found you=
r domain, we found your backlinks, and we can find you better backlinks to =
improve your Google rankings.</div><div>=C2=A0</div><div>Our team at Big Fa=
t Links is here to provide a dedicated service. We deliver high-quality bac=
klinks that help drive your search terms to the top of the search engines' =
rankings, and we ensure our backlinks drive the traffic that's important to=
 you, traffic that has buying/converting intent, and solutions that help yo=
u deliver your online goals.</div><div><br></div><div>We believe in quality=
 over quantity and in exceeding your expectations. We back that up with a=
=C2=A0<strong>money-back guarantee</strong>!</div><div><br></div><div>If yo=
u want a service from reputable experts who have been in the industry for m=
any years, working with over 1,500 clients, then drop me a line today, or v=
isit <a href=3D"http://Bigfatlinks.com" rel=3D"noopener noreferrer" target=
=3D"_blank">Bigfatlinks.com</a>
</div><div><br></div><div>Thanks</div><br><div>Big Fat Links</div><div><a h=
ref=3D"http://www.bigfatlinks.com" target=3D"_blank">Big Fat Links Ltd</a><=
/div><div> 1 mann island, wilmslow, cheshire east, united kingdom</div><img=
 style=3D'width:0px;max-height:0px;overflow:hidden;display:block' src =3D '=
https://t.brave-alpaca.com/+?y=3D49ii4eh26orjgc9jckr3gc1p6dhjie1g60o32d1icc=
q3ed92' alt=3D''></div>If you don't want to hear from me again, please <a h=
ref=3D'https://t.brave-alpaca.com/u?mid=3D67813e68093c98000142c475'>let me =
know</a>.

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/9hmmszvh2dngpt2feoukg6038.D73J3ACG9X04%40connect.bigfatlinks.tech=
?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/=
kasan-dev/9hmmszvh2dngpt2feoukg6038.D73J3ACG9X04%40connect.bigfatlinks.tech=
</a>.<br />

--altpart-9a65524b43b4207fe2dfc111bdb37c1307de5f6a5746329819bf442b2a31--

--9a65524b43b4207fe2dfc111bdb37c1307de5f6a5746329819bf442b2a31--
